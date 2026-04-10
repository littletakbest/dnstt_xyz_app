import 'package:flutter/foundation.dart';
import '../data/dns_presets.dart';
import '../models/dns_server.dart';
import '../models/dnstt_config.dart';
import '../services/storage_service.dart';
import '../services/dnstt_service.dart';
import '../services/system_dns_service.dart';

enum ConnectionStatus { disconnected, connecting, connected, error }

class AppLogEntry {
  final DateTime timestamp;
  final String message;

  const AppLogEntry({required this.timestamp, required this.message});

  String get timestampLabel {
    final month = timestamp.month.toString().padLeft(2, '0');
    final day = timestamp.day.toString().padLeft(2, '0');
    final hour = timestamp.hour.toString().padLeft(2, '0');
    final minute = timestamp.minute.toString().padLeft(2, '0');
    final second = timestamp.second.toString().padLeft(2, '0');
    final millisecond = timestamp.millisecond.toString().padLeft(3, '0');
    return '$month-$day $hour:$minute:$second.$millisecond';
  }
}

class AppState extends ChangeNotifier {
  StorageService? _storage;
  List<DnsServer> _dnsServers = [];
  List<DnsttConfig> _dnsttConfigs = [];
  DnsttConfig? _activeConfig;
  DnsServer? _activeDns;
  String? _activeDnsId;
  ConnectionStatus _connectionStatus = ConnectionStatus.disconnected;
  String? _connectionError;
  Map<String, bool> _testingDns = {};
  bool _isTestingAll = false;
  bool _cancelTestingRequested = false;
  int _testingProgress = 0;
  int _testingTotal = 0;
  int _testingWorking = 0;
  int _testingFailed = 0;
  String _testUrl = 'https://www.google.com';
  int _proxyPort = StorageService.defaultProxyPort;
  String _connectionMode = 'vpn';
  bool _strictDnsMode = true;
  DnsServer? _autoDnsServer;
  String? _autoDnsError;
  final List<AppLogEntry> _logs = [];
  DnsServer get localDnsPlaceholder =>
      DnsPresets.all().firstWhere((s) => s.id == DnsServer.localDnsId);

  List<DnsServer> get dnsServers => _dnsServers;
  List<DnsServer> get visibleDnsServers => [
    _autoDnsServer ??
        localDnsPlaceholder.copyWith(lastTestMessage: _autoDnsError),
    ..._dnsServers,
  ];
  List<DnsttConfig> get dnsttConfigs => _dnsttConfigs;
  DnsttConfig? get activeConfig => _activeConfig;
  DnsServer? get activeDns =>
      _activeDnsId == DnsServer.localDnsId ? _autoDnsServer : _activeDns;
  bool get useAutoDns => _activeDnsId == DnsServer.localDnsId;
  String? get autoDnsError => _autoDnsError;
  ConnectionStatus get connectionStatus => _connectionStatus;
  String? get connectionError => _connectionError;
  bool get isTestingAll => _isTestingAll;
  bool isDnsBeingTested(String id) => _testingDns[id] ?? false;
  String get testUrl => _testUrl;
  int get proxyPort => _proxyPort;
  String get connectionMode => _connectionMode;
  bool get strictDnsMode => _strictDnsMode;
  List<AppLogEntry> get logs => List.unmodifiable(_logs);
  bool get isAndroidVpnMode =>
      defaultTargetPlatform == TargetPlatform.android &&
      _connectionMode == 'vpn';
  bool get isStrictDnsActive => isAndroidVpnMode && _strictDnsMode;
  DnsServer? get effectiveAppDns {
    final resolver = activeDns;
    if (resolver == null) return null;
    if (!isStrictDnsActive) return resolver;
    if (resolver.isSystemResolver) {
      return DnsPresets.googleFallback();
    }
    return resolver;
  }

  int get testingProgress => _testingProgress;
  int get testingTotal => _testingTotal;
  int get testingWorking => _testingWorking;
  int get testingFailed => _testingFailed;

  List<DnsServer> get workingDnsServers =>
      visibleDnsServers.where((s) => s.isWorking).toList();

  Future<void> init(StorageService storage) async {
    _storage = storage;
    await _loadData();
  }

  Future<void> _loadData() async {
    _dnsServers = _mergePresetServers(await _storage!.getDnsServers());
    _dnsttConfigs = await _storage!.getDnsttConfigs();

    final activeConfigId = await _storage!.getActiveConfigId();
    if (activeConfigId != null) {
      _activeConfig = _dnsttConfigs
          .where((c) => c.id == activeConfigId)
          .firstOrNull;
    }

    final activeDnsId = await _storage!.getActiveDnsId();
    _activeDnsId = activeDnsId;
    if (activeDnsId != null) {
      _activeDns = _dnsServers.where((s) => s.id == activeDnsId).firstOrNull;
    }

    _testUrl = await _storage!.getTestUrl() ?? 'https://www.google.com';
    _proxyPort = await _storage!.getProxyPort();
    _connectionMode = await _storage!.getConnectionMode() ?? 'vpn';
    _strictDnsMode = await _storage!.getStrictDnsMode();

    await _detectSystemDns();

    if (_activeDnsId == DnsServer.localDnsId) {
      _activeDns = null;
    }

    notifyListeners();
  }

  List<DnsServer> _mergePresetServers(List<DnsServer> storedServers) {
    final byKey = <String, DnsServer>{};

    for (final preset in DnsPresets.persistentPresets()) {
      byKey[preset.resolverKey] = preset;
    }

    for (final server in storedServers) {
      final existing = byKey[server.resolverKey];
      if (existing != null && existing.isPreset) {
        byKey[server.resolverKey] = existing.copyWith(
          name: server.name ?? existing.name,
          region: server.region ?? existing.region,
          provider: server.provider ?? existing.provider,
          bootstrapAddress:
              server.bootstrapAddress ?? existing.bootstrapAddress,
          isWorking: server.isWorking,
          lastTested: server.lastTested,
          lastLatencyMs: server.lastLatencyMs,
          lastTestMessage: server.lastTestMessage,
        );
      } else {
        byKey[server.resolverKey] = server;
      }
    }

    return byKey.values.toList();
  }

  // DNS Server Management
  Future<void> addDnsServer(DnsServer server) async {
    final existingIndex = _dnsServers.indexWhere(
      (s) => s.resolverKey == server.resolverKey,
    );
    if (existingIndex == -1) {
      _dnsServers.insert(0, server);
    } else {
      _dnsServers[existingIndex] = server;
    }
    await _storage!.saveDnsServers(_dnsServers);
    notifyListeners();
  }

  Future<void> addDnsServers(List<DnsServer> servers) async {
    for (final server in servers) {
      if (!_dnsServers.contains(server)) {
        _dnsServers.add(server);
      }
    }
    await _storage!.saveDnsServers(_dnsServers);
    notifyListeners();
  }

  /// Import DNS servers with deduplication based on IP address.
  /// If a server with the same IP already exists, only update its name if changed.
  /// Returns the count of new servers added and updated servers.
  Future<({int added, int updated})> importDnsServers(
    List<DnsServer> servers,
  ) async {
    int added = 0;
    int updated = 0;
    final newServers = <DnsServer>[];

    for (final server in servers) {
      // Find existing server by IP address
      final existingIndex = _dnsServers.indexWhere(
        (s) => s.resolverKey == server.resolverKey,
      );

      if (existingIndex >= 0) {
        // Server exists - check if name needs update
        final existing = _dnsServers[existingIndex];
        if (server.name != null && server.name != existing.name) {
          // Update name only
          _dnsServers[existingIndex] = DnsServer(
            id: existing.id,
            address: existing.address,
            name: server.name,
            region: server.region ?? existing.region,
            provider: server.provider ?? existing.provider,
            resolverType: existing.resolverType,
            bootstrapAddress:
                server.bootstrapAddress ?? existing.bootstrapAddress,
            group: existing.group,
            isPreset: existing.isPreset,
            isWorking: existing.isWorking,
            lastTested: existing.lastTested,
            lastLatencyMs: existing.lastLatencyMs,
            lastTestMessage: existing.lastTestMessage,
          );
          updated++;
        }
      } else {
        // New server - collect for inserting at top
        newServers.add(server);
        added++;
      }
    }

    // Insert new servers at the top, preserving their order
    if (newServers.isNotEmpty) {
      _dnsServers.insertAll(0, newServers);
    }

    await _storage!.saveDnsServers(_dnsServers);
    notifyListeners();

    return (added: added, updated: updated);
  }

  Future<void> removeDnsServer(String id) async {
    if (id == DnsServer.localDnsId) {
      return;
    }
    await _storage!.removeDnsServer(id);
    _dnsServers = _mergePresetServers(await _storage!.getDnsServers());
    if (_activeDnsId == id) {
      _activeDns = null;
      _activeDnsId = null;
      await _storage!.setActiveDnsId(null);
    }
    notifyListeners();
  }

  Future<void> clearAllDnsServers() async {
    _dnsServers = DnsPresets.persistentPresets();
    await _storage!.saveDnsServers(_dnsServers);
    _activeDns = null;
    _activeDnsId = null;
    await _storage!.setActiveDnsId(null);
    notifyListeners();
  }

  Future<void> updateDnsServerStatus(
    String id,
    bool isWorking, {
    int? latencyMs,
    String? message,
  }) async {
    if (id == DnsServer.localDnsId && _autoDnsServer != null) {
      _autoDnsServer = _autoDnsServer!.copyWith(
        isWorking: isWorking,
        lastTested: DateTime.now(),
        lastLatencyMs: latencyMs,
        lastTestMessage: message,
      );
      notifyListeners();
      return;
    }

    final index = _dnsServers.indexWhere((s) => s.id == id);
    if (index == -1) return;
    final server = _dnsServers[index].copyWith(
      isWorking: isWorking,
      lastTested: DateTime.now(),
      lastLatencyMs: latencyMs,
      lastTestMessage: message,
    );
    _dnsServers[index] = server;
    await _storage!.updateDnsServer(server);
    notifyListeners();
  }

  // DNSTT Config Management
  Future<void> addDnsttConfig(DnsttConfig config) async {
    await _storage!.addDnsttConfig(config);
    _dnsttConfigs = await _storage!.getDnsttConfigs();
    notifyListeners();
  }

  /// Import multiple DNSTT configs with deduplication based on tunnelDomain + publicKey.
  /// Returns the count of new configs added and updated configs.
  Future<({int added, int updated})> importDnsttConfigs(
    List<DnsttConfig> configs,
  ) async {
    int added = 0;
    int updated = 0;

    for (final config in configs) {
      // Find existing config by domain and public key
      final existingIndex = _dnsttConfigs.indexWhere(
        (c) =>
            c.tunnelDomain == config.tunnelDomain &&
            c.publicKey == config.publicKey,
      );

      if (existingIndex >= 0) {
        // Config exists - update name if different
        final existing = _dnsttConfigs[existingIndex];
        if (config.name != existing.name) {
          existing.name = config.name;
          await _storage!.updateDnsttConfig(existing);
          updated++;
        }
      } else {
        // New config - add it
        await _storage!.addDnsttConfig(config);
        added++;
      }
    }

    _dnsttConfigs = await _storage!.getDnsttConfigs();
    notifyListeners();

    return (added: added, updated: updated);
  }

  Future<void> updateDnsttConfig(DnsttConfig config) async {
    await _storage!.updateDnsttConfig(config);
    _dnsttConfigs = await _storage!.getDnsttConfigs();
    if (_activeConfig?.id == config.id) {
      _activeConfig = config;
    }
    notifyListeners();
  }

  Future<void> removeDnsttConfig(String id) async {
    await _storage!.removeDnsttConfig(id);
    _dnsttConfigs = await _storage!.getDnsttConfigs();
    if (_activeConfig?.id == id) {
      _activeConfig = null;
      await _storage!.setActiveConfigId(null);
    }
    notifyListeners();
  }

  // Active selections
  Future<void> setActiveConfig(DnsttConfig? config) async {
    _activeConfig = config;
    await _storage!.setActiveConfigId(config?.id);
    notifyListeners();
  }

  Future<void> setActiveDns(DnsServer? dns) async {
    _activeDnsId = dns?.id;
    if (dns?.id == DnsServer.localDnsId) {
      await _detectSystemDns();
      _activeDns = null;
    } else {
      _activeDns = dns;
    }
    await _storage!.setActiveDnsId(dns?.id);
    notifyListeners();
  }

  // Testing
  void setDnsTesting(String id, bool testing) {
    _testingDns[id] = testing;
    notifyListeners();
  }

  void setTestingAll(bool testing) {
    _isTestingAll = testing;
    notifyListeners();
  }

  /// Start testing all DNS servers in the background
  /// This continues even when the user leaves the DNS management screen
  Future<void> startTestingAllDnsServers() async {
    if (_isTestingAll) return; // Already testing
    if (visibleDnsServers.isEmpty) return;

    _isTestingAll = true;
    _cancelTestingRequested = false;
    _testingProgress = 0;
    _testingTotal = visibleDnsServers.length;
    _testingWorking = 0;
    _testingFailed = 0;
    notifyListeners();

    final servers = List<DnsServer>.from(visibleDnsServers);

    try {
      await DnsttService.testMultipleResolvers(
        servers,
        concurrency: 3,
        timeout: const Duration(seconds: 8),
        shouldCancel: () => _cancelTestingRequested,
        onResult: (result) async {
          _testingProgress++;

          if (result.result == TestResult.success) {
            _testingWorking++;
          } else {
            _testingFailed++;
          }

          await updateDnsServerStatus(
            result.server.id,
            result.result == TestResult.success,
            latencyMs: result.latency?.inMilliseconds,
            message: result.message,
          );
        },
      );
    } finally {
      _isTestingAll = false;
      _cancelTestingRequested = false;

      // Sort servers by latency after testing (working first, then by latency)
      _sortServersByLatency();

      notifyListeners();
    }
  }

  /// Sort DNS servers: working (by latency) → not tested → failed
  void _sortServersByLatency() {
    _dnsServers.sort((a, b) {
      // Priority: working (0) > not tested (1) > failed (2)
      int priorityA = _getServerPriority(a);
      int priorityB = _getServerPriority(b);

      if (priorityA != priorityB) {
        return priorityA.compareTo(priorityB);
      }

      // Among working servers, sort by latency (lower is better)
      if (priorityA == 0) {
        final latencyA = a.lastLatencyMs ?? 999999;
        final latencyB = b.lastLatencyMs ?? 999999;
        return latencyA.compareTo(latencyB);
      }

      // Keep original order for not tested and failed servers
      return 0;
    });

    // Save sorted order to storage
    _storage?.saveDnsServers(_dnsServers);
  }

  /// Get priority for sorting: 0 = working, 1 = not tested, 2 = failed
  int _getServerPriority(DnsServer server) {
    if (server.lastTested == null) {
      return 1; // Not tested
    } else if (server.isWorking) {
      return 0; // Working
    } else {
      return 2; // Failed
    }
  }

  String? getResolverSupportMessage(DnsServer server) {
    if (server.isSystemResolver && _autoDnsServer == null) {
      return _autoDnsError ?? 'Could not detect the local resolver address';
    }
    return null;
  }

  String describeConnectionFailure(String? rawError) {
    if (rawError == null || rawError.trim().isEmpty) {
      return 'VPN connection failed';
    }

    final resolver = activeDns;
    final lower = rawError.toLowerCase();

    if (lower.contains('dns server not responding')) {
      final resolverName = resolver?.displayName ?? 'the selected DNS server';
      final baseMessage =
          'DNSTT could not bootstrap through $resolverName. '
          'The resolver may answer normal DNS queries, but DNSTT tunnel TXT/EDNS queries timed out.';

      if (resolver != null &&
          (resolver.isUdpResolver || resolver.isSystemResolver)) {
        return '$baseMessage Try a DoH/DoT preset or another DNS provider. '
            'Details: $rawError';
      }
      return '$baseMessage Details: $rawError';
    }

    if (lower.contains('tunnel verification failed')) {
      return 'The tunnel started but traffic verification failed. '
          'Check the tunnel domain/public key and try another DNS preset if needed. '
          'Details: $rawError';
    }

    return rawError;
  }

  String get bootstrapDnsLabel {
    final resolver = activeDns;
    if (resolver == null) return 'No DNS selected';
    if (resolver.isSystemResolver) {
      return '${resolver.displayAddress} (detected local resolver)';
    }
    return resolver.displayName;
  }

  String get appDnsLabel {
    final resolver = effectiveAppDns;
    if (resolver == null) return 'No DNS selected';
    if (isStrictDnsActive &&
        activeDns?.isSystemResolver == true &&
        resolver.id == DnsPresets.googleFallback().id) {
      return '${resolver.displayName} (fallback)';
    }
    return resolver.displayName;
  }

  /// Test a single DNS server
  Future<void> testSingleDnsServer(DnsServer server) async {
    if (_testingDns[server.id] == true) return; // Already testing this server

    final supportMessage = getResolverSupportMessage(server);
    if (supportMessage != null) {
      await updateDnsServerStatus(server.id, false, message: supportMessage);
      return;
    }

    _testingDns[server.id] = true;
    notifyListeners();

    try {
      final result = await DnsttService.testResolver(
        server,
        timeout: const Duration(seconds: 8),
      );

      await updateDnsServerStatus(
        server.id,
        result.result == TestResult.success,
        latencyMs: result.latency?.inMilliseconds,
        message: result.message,
      );
    } finally {
      _testingDns[server.id] = false;
      notifyListeners();
    }
  }

  /// Cancel the ongoing test
  Future<void> cancelTesting() async {
    if (_isTestingAll) {
      _cancelTestingRequested = true;
      notifyListeners();
    }
  }

  // Auto DNS
  Future<void> setUseAutoDns(bool value) async {
    await setActiveDns(value ? (_autoDnsServer ?? localDnsPlaceholder) : null);
    notifyListeners();
  }

  Future<void> _detectSystemDns() async {
    _autoDnsError = null;
    final addr = await SystemDnsService.detectSystemDns();
    if (addr != null) {
      final existingStatus = _autoDnsServer;
      _autoDnsServer = DnsServer(
        id: DnsServer.localDnsId,
        address: addr,
        bootstrapAddress: addr,
        name: 'Detected Local Resolver',
        provider: 'System network',
        group: 'local',
        isPreset: true,
        resolverType: DnsResolverType.system,
        isWorking: existingStatus?.isWorking ?? false,
        lastTested: existingStatus?.lastTested,
        lastLatencyMs: existingStatus?.lastLatencyMs,
        lastTestMessage: existingStatus?.lastTestMessage,
      );
    } else {
      _autoDnsServer = null;
      _autoDnsError = 'Could not detect the local resolver address';
    }
  }

  Future<void> refreshAutoDns() async {
    if (!useAutoDns) return;
    await _detectSystemDns();
    notifyListeners();
  }

  // Connection
  void setConnectionStatus(ConnectionStatus status, [String? error]) {
    _connectionStatus = status;
    _connectionError = error;
    final details = error == null || error.trim().isEmpty ? null : error.trim();
    final message = switch (status) {
      ConnectionStatus.connected => 'Connection established',
      ConnectionStatus.connecting => 'Connecting',
      ConnectionStatus.disconnected => 'Disconnected',
      ConnectionStatus.error =>
        details == null ? 'Connection error' : 'Connection error: $details',
    };
    addLog(message);
    notifyListeners();
  }

  void addLog(String message) {
    _logs.add(AppLogEntry(timestamp: DateTime.now(), message: message));
    if (_logs.length > 200) {
      _logs.removeRange(0, _logs.length - 200);
    }
    notifyListeners();
  }

  void clearLogs() {
    _logs.clear();
    notifyListeners();
  }

  // Test URL
  Future<void> setTestUrl(String url) async {
    _testUrl = url;
    await _storage!.setTestUrl(url);
    notifyListeners();
  }

  // Proxy Port
  Future<void> setProxyPort(int port) async {
    _proxyPort = port;
    await _storage!.setProxyPort(port);
    notifyListeners();
  }

  // Connection Mode (Android: 'vpn' or 'proxy')
  Future<void> setConnectionMode(String mode) async {
    _connectionMode = mode;
    await _storage!.setConnectionMode(mode);
    notifyListeners();
  }

  Future<void> setStrictDnsMode(bool value) async {
    _strictDnsMode = value;
    await _storage!.setStrictDnsMode(value);
    notifyListeners();
  }
}
