import 'dart:convert';

import 'package:dnstt_xyz_app/models/dnstt_config.dart';
import 'package:dnstt_xyz_app/services/config_import_export_service.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('SSH configs export and import private keys', () {
    const privateKey = '''
-----BEGIN OPENSSH PRIVATE KEY-----
test-private-key
-----END OPENSSH PRIVATE KEY-----
''';

    final jsonString = ConfigImportExportService.exportConfigsToJson([
      DnsttConfig(
        name: 'SSH Key Config',
        publicKey: 'a' * 64,
        tunnelDomain: 't.example.com',
        tunnelType: TunnelType.ssh,
        sshUsername: 'demo',
        sshPrivateKey: privateKey,
      ),
    ]);

    final decoded = json.decode(jsonString) as Map<String, dynamic>;
    final configs = decoded['configs'] as List<dynamic>;
    expect(configs, hasLength(1));
    expect(configs.first['sshPrivateKey'], privateKey);

    final imported = ConfigImportExportService.importConfigsFromJson(
      jsonString,
    );
    expect(imported, hasLength(1));
    expect(imported.first.sshUsername, 'demo');
    expect(imported.first.sshPrivateKey, privateKey);
    expect(imported.first.sshPassword, isNull);
  });
}
