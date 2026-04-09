import 'package:flutter_test/flutter_test.dart';
import 'package:dnstt_xyz_app/models/dns_server.dart';

void main() {
  test('legacy DNS entries deserialize as UDP resolvers', () {
    final server = DnsServer.fromJson({
      'id': 'legacy-google',
      'address': '8.8.8.8',
      'name': 'Google DNS',
    });

    expect(server.isUdpResolver, isTrue);
    expect(server.address, '8.8.8.8');
    expect(server.connectAddress, '8.8.8.8');
  });
}
