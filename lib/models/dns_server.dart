import 'package:uuid/uuid.dart';

enum DnsResolverType { udp, doh, dot, system }

extension DnsResolverTypeWire on DnsResolverType {
  String get wireName => switch (this) {
    DnsResolverType.udp => 'udp',
    DnsResolverType.doh => 'doh',
    DnsResolverType.dot => 'dot',
    DnsResolverType.system => 'system',
  };

  static DnsResolverType fromWireName(String? value) {
    return switch (value) {
      'doh' => DnsResolverType.doh,
      'dot' => DnsResolverType.dot,
      'system' => DnsResolverType.system,
      _ => DnsResolverType.udp,
    };
  }
}

class DnsServer {
  static const String localDnsId = 'system-local-dns';

  final String id;
  final String address;
  final String? name;
  final String? region;
  final String? provider;
  final DnsResolverType resolverType;
  final String? bootstrapAddress;
  final String? group;
  final bool isPreset;
  bool isWorking;
  DateTime? lastTested;
  int? lastLatencyMs;
  String? lastTestMessage;

  DnsServer({
    String? id,
    required this.address,
    this.name,
    this.region,
    this.provider,
    this.resolverType = DnsResolverType.udp,
    this.bootstrapAddress,
    this.group,
    this.isPreset = false,
    this.isWorking = false,
    this.lastTested,
    this.lastLatencyMs,
    this.lastTestMessage,
  }) : id = id ?? const Uuid().v4();

  bool get isSystemResolver => resolverType == DnsResolverType.system;
  bool get isUdpResolver => resolverType == DnsResolverType.udp;
  bool get isDohResolver => resolverType == DnsResolverType.doh;
  bool get isDotResolver => resolverType == DnsResolverType.dot;

  String get displayName => name ?? address;

  String get displayAddress {
    if (isSystemResolver) {
      return bootstrapAddress ?? address;
    }
    return address;
  }

  String get connectAddress => bootstrapAddress ?? address;

  String get resolverValue => switch (resolverType) {
    DnsResolverType.system => connectAddress,
    _ => address,
  };

  String get subtitleText {
    final parts = <String>[
      if (provider != null && provider!.isNotEmpty) provider!,
      if (region != null && region!.isNotEmpty) region!,
      switch (resolverType) {
        DnsResolverType.udp => 'UDP',
        DnsResolverType.doh => 'DoH',
        DnsResolverType.dot => 'DoT',
        DnsResolverType.system => 'Detected local resolver',
      },
    ];
    return parts.join(' - ');
  }

  String get resolverKey => '${resolverType.wireName}|$address';

  Map<String, dynamic> toJson() => {
    'id': id,
    'address': address,
    'name': name,
    'region': region,
    'provider': provider,
    'resolverType': resolverType.wireName,
    'bootstrapAddress': bootstrapAddress,
    'group': group,
    'isPreset': isPreset,
    'isWorking': isWorking,
    'lastTested': lastTested?.toIso8601String(),
    'lastLatencyMs': lastLatencyMs,
    'lastTestMessage': lastTestMessage,
  };

  factory DnsServer.fromJson(Map<String, dynamic> json) {
    final resolverType = DnsResolverTypeWire.fromWireName(
      json['resolverType'] as String?,
    );
    final address = json['address'] as String;
    final bootstrapAddress =
        (json['bootstrapAddress'] as String?) ??
        (resolverType == DnsResolverType.udp ? address : null);

    return DnsServer(
      id: json['id'] as String?,
      address: address,
      name: json['name'] as String?,
      region: json['region'] as String?,
      provider: json['provider'] as String?,
      resolverType: resolverType,
      bootstrapAddress: bootstrapAddress,
      group: json['group'] as String?,
      isPreset: json['isPreset'] ?? false,
      isWorking: json['isWorking'] ?? false,
      lastTested: json['lastTested'] != null
          ? DateTime.parse(json['lastTested'])
          : null,
      lastLatencyMs: json['lastLatencyMs'] as int?,
      lastTestMessage: json['lastTestMessage'] as String?,
    );
  }

  DnsServer copyWith({
    String? id,
    String? address,
    String? name,
    String? region,
    String? provider,
    DnsResolverType? resolverType,
    String? bootstrapAddress,
    String? group,
    bool? isPreset,
    bool? isWorking,
    DateTime? lastTested,
    int? lastLatencyMs,
    String? lastTestMessage,
  }) {
    return DnsServer(
      id: id ?? this.id,
      address: address ?? this.address,
      name: name ?? this.name,
      region: region ?? this.region,
      provider: provider ?? this.provider,
      resolverType: resolverType ?? this.resolverType,
      bootstrapAddress: bootstrapAddress ?? this.bootstrapAddress,
      group: group ?? this.group,
      isPreset: isPreset ?? this.isPreset,
      isWorking: isWorking ?? this.isWorking,
      lastTested: lastTested ?? this.lastTested,
      lastLatencyMs: lastLatencyMs ?? this.lastLatencyMs,
      lastTestMessage: lastTestMessage ?? this.lastTestMessage,
    );
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is DnsServer &&
          runtimeType == other.runtimeType &&
          resolverKey == other.resolverKey;

  @override
  int get hashCode => resolverKey.hashCode;
}
