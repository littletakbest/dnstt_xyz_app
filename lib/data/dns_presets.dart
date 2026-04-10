import '../models/dns_server.dart';

class DnsPresets {
  static List<DnsServer> all() {
    return [
      const _PresetFactory().localPlaceholder(),
      const _PresetFactory().googleUdp(),
      const _PresetFactory().cloudflareUdp(),
      const _PresetFactory().cloudflareDoh(),
      const _PresetFactory().cloudflareDot(),
      const _PresetFactory().aliDnsPrimary(),
      const _PresetFactory().dnsPod(),
      const _PresetFactory().oneOneFour(),
    ];
  }

  static List<DnsServer> persistentPresets() {
    return all().where((server) => !server.isSystemResolver).toList();
  }

  static DnsServer googleFallback() {
    return const _PresetFactory().googleUdp();
  }
}

class _PresetFactory {
  const _PresetFactory();

  DnsServer localPlaceholder() => DnsServer(
    id: DnsServer.localDnsId,
    address: '',
    name: 'Detected Local Resolver',
    provider: 'System network',
    group: 'local',
    isPreset: true,
    resolverType: DnsResolverType.system,
  );

  DnsServer googleUdp() => DnsServer(
    id: 'preset-google-udp',
    address: '8.8.8.8',
    bootstrapAddress: '8.8.8.8',
    name: 'Google DNS',
    provider: 'Google',
    group: 'global',
    isPreset: true,
  );

  DnsServer cloudflareUdp() => DnsServer(
    id: 'preset-cloudflare-udp',
    address: '1.1.1.1',
    bootstrapAddress: '1.1.1.1',
    name: 'Cloudflare 1.1.1.1',
    provider: 'Cloudflare',
    group: 'global',
    isPreset: true,
  );

  DnsServer cloudflareDoh() => DnsServer(
    id: 'preset-cloudflare-doh',
    address: 'https://1.1.1.1/dns-query',
    bootstrapAddress: '1.1.1.1',
    name: 'Cloudflare 1.1.1.1 DoH',
    provider: 'Cloudflare',
    group: 'global',
    isPreset: true,
    resolverType: DnsResolverType.doh,
  );

  DnsServer cloudflareDot() => DnsServer(
    id: 'preset-cloudflare-dot',
    address: '1.1.1.1:853',
    bootstrapAddress: '1.1.1.1',
    name: 'Cloudflare 1.1.1.1 DoT',
    provider: 'Cloudflare',
    group: 'global',
    isPreset: true,
    resolverType: DnsResolverType.dot,
  );

  DnsServer aliDnsPrimary() => DnsServer(
    id: 'preset-china-alidns',
    address: '223.5.5.5',
    bootstrapAddress: '223.5.5.5',
    name: 'AliDNS',
    provider: 'Alibaba',
    region: 'China',
    group: 'china',
    isPreset: true,
  );

  DnsServer dnsPod() => DnsServer(
    id: 'preset-china-dnspod',
    address: '119.29.29.29',
    bootstrapAddress: '119.29.29.29',
    name: 'DNSPod',
    provider: 'Tencent',
    region: 'China',
    group: 'china',
    isPreset: true,
  );

  DnsServer oneOneFour() => DnsServer(
    id: 'preset-china-114dns',
    address: '114.114.114.114',
    bootstrapAddress: '114.114.114.114',
    name: '114DNS',
    provider: '114DNS',
    region: 'China',
    group: 'china',
    isPreset: true,
  );
}
