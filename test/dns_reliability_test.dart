import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dnstt_xyz_app/data/dns_presets.dart';
import 'package:dnstt_xyz_app/models/dns_server.dart';
import 'package:dnstt_xyz_app/providers/app_state.dart';
import 'package:dnstt_xyz_app/services/dnstt_service.dart';
import 'package:dnstt_xyz_app/services/storage_service.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

class _RealHttpOverrides extends HttpOverrides {}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test(
    'strict DNS falls back only when using detected local resolver',
    () async {
      SharedPreferences.setMockInitialValues({});
      final storage = await StorageService.init();
      final state = AppState();
      await state.init(storage);

      final detectedLocalResolver = DnsServer(
        id: 'local-resolver-test',
        address: '192.0.2.10',
        bootstrapAddress: '192.0.2.10',
        name: 'Detected Local Resolver',
        resolverType: DnsResolverType.system,
      );

      await state.setConnectionMode('vpn');
      await state.setActiveDns(detectedLocalResolver);

      await state.setStrictDnsMode(true);
      expect(state.effectiveAppDns?.id, DnsPresets.googleFallback().id);

      await state.setStrictDnsMode(false);
      expect(state.effectiveAppDns?.id, detectedLocalResolver.id);
    },
  );

  test('batch resolver testing awaits async onResult callbacks', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(() => server.close(force: true));

    server.listen((request) async {
      Uint8List dnsQuery;
      if (request.method == 'GET') {
        final encodedQuery = request.uri.queryParameters['dns'];
        if (encodedQuery == null || encodedQuery.isEmpty) {
          request.response.statusCode = HttpStatus.badRequest;
          await request.response.close();
          return;
        }
        final normalizedQuery = switch (encodedQuery.length % 4) {
          2 => '$encodedQuery==',
          3 => '$encodedQuery=',
          _ => encodedQuery,
        };
        dnsQuery = Uint8List.fromList(base64Url.decode(normalizedQuery));
      } else {
        final requestBytes = await request.fold<BytesBuilder>(
          BytesBuilder(copy: false),
          (builder, chunk) {
            builder.add(chunk);
            return builder;
          },
        );
        dnsQuery = requestBytes.toBytes();
      }
      final response = Uint8List.fromList([
        dnsQuery[0],
        dnsQuery[1],
        0x81,
        0x80,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
      ]);
      request.response.statusCode = HttpStatus.ok;
      request.response.headers.contentType = ContentType(
        'application',
        'dns-message',
      );
      request.response.add(response);
      await request.response.close();
    });

    final resolverUrl =
        'http://${server.address.address}:${server.port}/dns-query';
    final resolvers = [
      DnsServer(
        id: 'resolver-a',
        address: resolverUrl,
        name: 'Resolver A',
        resolverType: DnsResolverType.doh,
      ),
      DnsServer(
        id: 'resolver-b',
        address: resolverUrl,
        name: 'Resolver B',
        resolverType: DnsResolverType.doh,
      ),
    ];

    final completedCallbacks = <String>[];
    final success = await HttpOverrides.runWithHttpOverrides(
      () => DnsttService.testMultipleResolvers(
        resolvers,
        concurrency: 2,
        onResult: (result) async {
          await Future<void>.delayed(const Duration(milliseconds: 20));
          completedCallbacks.add('${result.server.id}:${result.message}');
        },
      ),
      _RealHttpOverrides(),
    );

    expect(success, isTrue);
    expect(
      completedCallbacks,
      equals([
        'resolver-a:Resolver answered DNS',
        'resolver-b:Resolver answered DNS',
      ]),
    );
  });
}
