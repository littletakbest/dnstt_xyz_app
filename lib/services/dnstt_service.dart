import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';
import 'package:flutter/foundation.dart';
import 'package:socks5_proxy/socks_client.dart';
import '../models/dns_server.dart';
import '../models/dnstt_config.dart';
import 'dnstt_ffi_service.dart';
import 'slipstream_service.dart';
import 'vpn_service.dart';

enum TestResult { success, failed, timeout }

class TunnelTestResult {
  final TestResult result;
  final String? message;
  final Duration? latency;
  final int? statusCode;
  final String? responseBody;

  TunnelTestResult({
    required this.result,
    this.message,
    this.latency,
    this.statusCode,
    this.responseBody,
  });
}

class DnsttTestResult {
  final DnsServer server;
  final TestResult result;
  final String? message;
  final Duration? latency;

  DnsttTestResult({
    required this.server,
    required this.result,
    this.message,
    this.latency,
  });
}

class DnsttService {
  static const Duration testTimeout = Duration(seconds: 5);
  static const int _advertisedDnsUdpPayloadSize = 1232;

  // Base32 alphabet (RFC 4648 without padding)
  static const String _base32Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  /// Encodes bytes to base32 (no padding)
  static String _base32Encode(Uint8List data) {
    if (data.isEmpty) return '';

    final result = StringBuffer();
    int buffer = 0;
    int bitsLeft = 0;

    for (final byte in data) {
      buffer = (buffer << 8) | byte;
      bitsLeft += 8;

      while (bitsLeft >= 5) {
        bitsLeft -= 5;
        result.write(_base32Alphabet[(buffer >> bitsLeft) & 0x1F]);
      }
    }

    if (bitsLeft > 0) {
      result.write(_base32Alphabet[(buffer << (5 - bitsLeft)) & 0x1F]);
    }

    return result.toString().toLowerCase();
  }

  /// Builds a DNSTT-style DNS TXT query for the tunnel domain
  /// This mimics what the dnstt client sends
  static Uint8List _buildDnsttQuery(String tunnelDomain) {
    final random = Random.secure();
    final transactionId = random.nextInt(65535);

    // Generate a random client ID (8 bytes) like dnstt does
    final clientId = Uint8List(8);
    for (int i = 0; i < 8; i++) {
      clientId[i] = random.nextInt(256);
    }

    // Build the payload: clientID + padding indicator + padding
    final payload = BytesBuilder();
    payload.add(clientId);
    // Padding indicator: 224 + numPadding (we use 8 for poll)
    payload.addByte(224 + 8);
    // Add 8 bytes of random padding
    for (int i = 0; i < 8; i++) {
      payload.addByte(random.nextInt(256));
    }

    // Encode payload as base32
    final encoded = _base32Encode(payload.toBytes());

    // Split into labels (max 63 chars each)
    final labels = <String>[];
    var remaining = encoded;
    while (remaining.isNotEmpty) {
      final chunkSize = remaining.length > 63 ? 63 : remaining.length;
      labels.add(remaining.substring(0, chunkSize));
      remaining = remaining.substring(chunkSize);
    }

    // Add tunnel domain labels
    final domainParts = tunnelDomain.split('.');
    labels.addAll(domainParts);

    // Build DNS query
    final query = BytesBuilder();

    // Transaction ID (2 bytes)
    query.addByte((transactionId >> 8) & 0xFF);
    query.addByte(transactionId & 0xFF);

    // Flags: standard query with RD (recursion desired)
    query.addByte(0x01);
    query.addByte(0x00);

    // Questions: 1
    query.addByte(0x00);
    query.addByte(0x01);

    // Answer RRs: 0
    query.addByte(0x00);
    query.addByte(0x00);

    // Authority RRs: 0
    query.addByte(0x00);
    query.addByte(0x00);

    // Additional RRs: 1 (for EDNS0 OPT)
    query.addByte(0x00);
    query.addByte(0x01);

    // Build QNAME from labels
    for (final label in labels) {
      query.addByte(label.length);
      query.add(utf8.encode(label));
    }
    query.addByte(0); // null terminator

    // Type: TXT (16)
    query.addByte(0x00);
    query.addByte(0x10);

    // Class: IN (1)
    query.addByte(0x00);
    query.addByte(0x01);

    // EDNS0 OPT record. Keep the advertised UDP size conservative so the test
    // query matches the mobile client and avoids fragmentation-prone payloads.
    query.addByte(0x00); // Name: root
    query.addByte(0x00); // Type: OPT (41)
    query.addByte(0x29);
    query.addByte((_advertisedDnsUdpPayloadSize >> 8) & 0xFF);
    query.addByte(_advertisedDnsUdpPayloadSize & 0xFF);
    query.addByte(0x00); // Extended RCODE
    query.addByte(0x00); // Version
    query.addByte(0x00); // Flags
    query.addByte(0x00);
    query.addByte(0x00); // RDATA length: 0
    query.addByte(0x00);

    return query.toBytes();
  }

  /// Builds a simple DNS query for google.com (for basic connectivity test)
  static Uint8List _buildSimpleDnsQuery() {
    final random = Random();
    final transactionId = random.nextInt(65535);

    // DNS query for google.com A record
    final query = BytesBuilder();

    // Transaction ID (2 bytes)
    query.addByte((transactionId >> 8) & 0xFF);
    query.addByte(transactionId & 0xFF);

    // Flags: standard query (2 bytes)
    query.addByte(0x01); // RD (recursion desired)
    query.addByte(0x00);

    // Questions: 1
    query.addByte(0x00);
    query.addByte(0x01);

    // Answer RRs: 0
    query.addByte(0x00);
    query.addByte(0x00);

    // Authority RRs: 0
    query.addByte(0x00);
    query.addByte(0x00);

    // Additional RRs: 0
    query.addByte(0x00);
    query.addByte(0x00);

    // Query: google.com
    query.addByte(6); // length of "google"
    query.add('google'.codeUnits);
    query.addByte(3); // length of "com"
    query.add('com'.codeUnits);
    query.addByte(0); // null terminator

    // Type: A (1)
    query.addByte(0x00);
    query.addByte(0x01);

    // Class: IN (1)
    query.addByte(0x00);
    query.addByte(0x01);

    return query.toBytes();
  }

  /// Check if we're on a desktop platform
  static bool get isDesktopPlatform =>
      Platform.isMacOS || Platform.isWindows || Platform.isLinux;

  /// Tests if a DNS server works with the tunnel (DNSTT or Slipstream)
  /// On both desktop and mobile (Android): Actually connects through the tunnel and makes HTTP request
  /// Fallback to DNS query test when no config available
  static Future<DnsttTestResult> testDnsServer(
    DnsServer server, {
    String? tunnelDomain,
    String? publicKey,
    String testUrl = 'https://api.ipify.org?format=json',
    Duration timeout = const Duration(seconds: 15),
    TransportType transportType = TransportType.dnstt,
    String congestionControl = 'dcubic',
    int keepAliveInterval = 400,
    bool gso = false,
  }) async {
    // Slipstream transport
    if (transportType == TransportType.slipstream && tunnelDomain != null) {
      return _testDnsServerViaSlipstream(
        server,
        tunnelDomain: tunnelDomain,
        testUrl: testUrl,
        timeout: timeout,
        congestionControl: congestionControl,
        keepAliveInterval: keepAliveInterval,
        gso: gso,
      );
    }

    // DNSTT transport: use real tunnel test when we have config
    if (tunnelDomain != null && publicKey != null) {
      return _testDnsServerViaTunnel(
        server,
        tunnelDomain: tunnelDomain,
        publicKey: publicKey,
        testUrl: testUrl,
        timeout: timeout,
      );
    }

    // Fallback to DNS query test when no config
    return _testDnsServerViaDnsQuery(
      server,
      tunnelDomain: tunnelDomain,
      timeout: timeout,
    );
  }

  /// Tests whether the resolver itself answers DNS queries, without using the tunnel.
  static Future<DnsttTestResult> testResolver(
    DnsServer server, {
    Duration timeout = testTimeout,
  }) async {
    debugPrint(
      'DnsTest start resolver=${server.displayName} '
      'type=${server.resolverType.wireName} value=${server.resolverValue}',
    );

    switch (server.resolverType) {
      case DnsResolverType.udp:
      case DnsResolverType.system:
        return _testDnsServerViaDnsQuery(server, timeout: timeout);
      case DnsResolverType.doh:
        return _testDnsServerViaDoh(server, timeout: timeout);
      case DnsResolverType.dot:
        return _testDnsServerViaDot(server, timeout: timeout);
    }
  }

  /// Test DNS server using Slipstream transport
  static Future<DnsttTestResult> _testDnsServerViaSlipstream(
    DnsServer server, {
    required String tunnelDomain,
    required String testUrl,
    required Duration timeout,
    String congestionControl = 'dcubic',
    int keepAliveInterval = 400,
    bool gso = false,
  }) async {
    if (isDesktopPlatform) {
      // Desktop: use SlipstreamService subprocess
      try {
        final result = await SlipstreamService.instance.testServer(
          domain: tunnelDomain,
          dnsServerAddr: server.connectAddress,
          testUrl: testUrl,
          timeoutMs: timeout.inMilliseconds,
          congestionControl: congestionControl,
          keepAliveInterval: keepAliveInterval,
          gso: gso,
        );

        if (result >= 0) {
          return DnsttTestResult(
            server: server,
            result: TestResult.success,
            message: 'Tunnel bootstrap succeeded',
            latency: Duration(milliseconds: result),
          );
        } else {
          return DnsttTestResult(
            server: server,
            result: TestResult.failed,
            message: 'Connection failed',
          );
        }
      } catch (e) {
        return DnsttTestResult(
          server: server,
          result: TestResult.failed,
          message: 'Error: $e',
        );
      }
    }

    // Mobile: use method channel
    try {
      final vpnService = VpnService();
      await vpnService.init();

      final result = await vpnService.testSlipstreamDnsServer(
        resolver: server,
        tunnelDomain: tunnelDomain,
        testUrl: testUrl,
        timeoutMs: timeout.inMilliseconds,
        congestionControl: congestionControl,
        keepAliveInterval: keepAliveInterval,
        gso: gso,
      );

      if (result >= 0) {
        return DnsttTestResult(
          server: server,
          result: TestResult.success,
          message: 'Tunnel bootstrap succeeded',
          latency: Duration(milliseconds: result),
        );
      } else if (result == -2) {
        return DnsttTestResult(
          server: server,
          result: TestResult.failed,
          message: 'Cancelled',
        );
      } else {
        return DnsttTestResult(
          server: server,
          result: TestResult.failed,
          message: 'Connection failed',
        );
      }
    } catch (e) {
      return DnsttTestResult(
        server: server,
        result: TestResult.failed,
        message: 'Error: $e',
      );
    }
  }

  /// Test DNS server using actual tunnel connection (works on desktop and mobile)
  static Future<DnsttTestResult> _testDnsServerViaTunnel(
    DnsServer server, {
    required String tunnelDomain,
    required String publicKey,
    required String testUrl,
    required Duration timeout,
  }) async {
    // On desktop, run the FFI test in a separate isolate to avoid blocking UI
    if (isDesktopPlatform) {
      return _testDnsServerInIsolate(
        server: server,
        tunnelDomain: tunnelDomain,
        publicKey: publicKey,
        testUrl: testUrl,
        timeoutMs: timeout.inMilliseconds,
      );
    }

    // On mobile, use method channel (already async)
    final stopwatch = Stopwatch()..start();
    try {
      final vpnService = VpnService();
      await vpnService.init();

      final result = await vpnService.testDnsServer(
        resolver: server,
        tunnelDomain: tunnelDomain,
        publicKey: publicKey,
        testUrl: testUrl,
        timeoutMs: timeout.inMilliseconds,
      );

      stopwatch.stop();

      if (result >= 0) {
        return DnsttTestResult(
          server: server,
          result: TestResult.success,
          message: 'Tunnel bootstrap succeeded',
          latency: Duration(milliseconds: result),
        );
      } else if (result == -2) {
        // Cancelled
        return DnsttTestResult(
          server: server,
          result: TestResult.failed,
          message: 'Cancelled',
        );
      } else {
        return DnsttTestResult(
          server: server,
          result: TestResult.failed,
          message: 'Connection failed',
        );
      }
    } catch (e) {
      stopwatch.stop();
      return DnsttTestResult(
        server: server,
        result: TestResult.failed,
        message: 'Error: $e',
      );
    }
  }

  /// Run the FFI test in a separate isolate to avoid blocking the UI
  static Future<DnsttTestResult> _testDnsServerInIsolate({
    required DnsServer server,
    required String tunnelDomain,
    required String publicKey,
    required String testUrl,
    required int timeoutMs,
  }) async {
    try {
      // Use compute to run in a separate isolate
      final result = await compute(_runFfiTest, {
        'dnsServer': server.address,
        'resolverType': server.resolverType.wireName,
        'resolverValue': server.resolverValue,
        'tunnelDomain': tunnelDomain,
        'publicKey': publicKey,
        'testUrl': testUrl,
        'timeoutMs': timeoutMs,
      });

      if (result >= 0) {
        return DnsttTestResult(
          server: server,
          result: TestResult.success,
          message: 'Tunnel bootstrap succeeded',
          latency: Duration(milliseconds: result),
        );
      } else {
        return DnsttTestResult(
          server: server,
          result: TestResult.failed,
          message: 'Connection failed',
        );
      }
    } catch (e) {
      return DnsttTestResult(
        server: server,
        result: TestResult.failed,
        message: 'Error: $e',
      );
    }
  }

  /// Test DNS server using DNS query (mobile fallback)
  static Future<DnsttTestResult> _testDnsServerViaDnsQuery(
    DnsServer server, {
    String? tunnelDomain,
    Duration timeout = testTimeout,
  }) async {
    final stopwatch = Stopwatch()..start();
    RawDatagramSocket? socket;

    try {
      debugPrint(
        'DnsTest udp resolver=${server.displayName} target=${server.connectAddress} '
        'mode=${tunnelDomain != null && tunnelDomain.isNotEmpty ? 'tunnel' : 'resolver'}',
      );

      // Create UDP socket
      socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);

      final udpAddress = InternetAddress.tryParse(server.connectAddress);
      if (udpAddress == null) {
        stopwatch.stop();
        return DnsttTestResult(
          server: server,
          result: TestResult.failed,
          message: 'Invalid IP address',
        );
      }

      // Build DNS query - use DNSTT format if tunnel domain provided
      final Uint8List query;
      final bool isDnsttTest = tunnelDomain != null && tunnelDomain.isNotEmpty;
      if (isDnsttTest) {
        query = _buildDnsttQuery(tunnelDomain);
      } else {
        query = _buildSimpleDnsQuery();
      }
      final expectedTransactionId = _transactionIdFromWire(query);

      socket.send(query, udpAddress, 53);

      // Wait for response with timeout
      final completer = Completer<DnsttTestResult>();
      Timer? timeoutTimer;

      timeoutTimer = Timer(timeout, () {
        if (!completer.isCompleted) {
          completer.complete(
            DnsttTestResult(
              server: server,
              result: TestResult.timeout,
              message: isDnsttTest
                  ? 'DNSTT bootstrap timed out'
                  : 'Resolver query timed out',
            ),
          );
        }
      });

      socket.listen((event) {
        if (event == RawSocketEvent.read && !completer.isCompleted) {
          final datagram = socket?.receive();
          if (datagram == null) {
            return;
          }

          if (datagram.address != udpAddress || datagram.port != 53) {
            debugPrint(
              'DnsTest udp ignore-source resolver=${server.displayName} '
              'source=${datagram.address.address}:${datagram.port}',
            );
            return;
          }

          if (datagram.data.length < 12) {
            stopwatch.stop();
            timeoutTimer?.cancel();
            completer.complete(
              DnsttTestResult(
                server: server,
                result: TestResult.failed,
                message: 'Invalid DNS response',
              ),
            );
            return;
          }

          final responseTransactionId = _transactionIdFromWire(datagram.data);
          if (responseTransactionId != expectedTransactionId) {
            debugPrint(
              'DnsTest udp ignore-transaction resolver=${server.displayName} '
              'expected=$expectedTransactionId actual=$responseTransactionId',
            );
            return;
          }

          stopwatch.stop();
          timeoutTimer?.cancel();

          if (_isTruncatedDnsResponse(datagram.data)) {
            completer.complete(
              DnsttTestResult(
                server: server,
                result: TestResult.failed,
                message: 'Resolver response was truncated',
              ),
            );
            return;
          }

          // Check if it's a valid DNS response
          final flags = datagram.data[2];
          final isResponse = (flags & 0x80) != 0;

          // Check RCODE (last 4 bits of second flag byte)
          final rcode = datagram.data[3] & 0x0F;

          if (!isResponse) {
            debugPrint(
              'DnsTest udp invalid-response resolver=${server.displayName}',
            );
            completer.complete(
              DnsttTestResult(
                server: server,
                result: TestResult.failed,
                message: 'Invalid DNS response',
              ),
            );
            return;
          }

          if (isDnsttTest) {
            if (rcode == 0) {
              final answerCount = (datagram.data[6] << 8) | datagram.data[7];
              if (answerCount > 0) {
                debugPrint(
                  'DnsTest udp bootstrap-success resolver=${server.displayName} '
                  'latency=${stopwatch.elapsedMilliseconds}ms answers=$answerCount',
                );
                completer.complete(
                  DnsttTestResult(
                    server: server,
                    result: TestResult.success,
                    message: 'Tunnel bootstrap succeeded',
                    latency: stopwatch.elapsed,
                  ),
                );
              } else {
                completer.complete(
                  DnsttTestResult(
                    server: server,
                    result: TestResult.failed,
                    message: 'Bootstrap query answered without TXT data',
                  ),
                );
              }
            } else if (rcode == 3) {
              completer.complete(
                DnsttTestResult(
                  server: server,
                  result: TestResult.failed,
                  message: 'DNSTT bootstrap returned NXDOMAIN',
                ),
              );
            } else if (rcode == 2) {
              completer.complete(
                DnsttTestResult(
                  server: server,
                  result: TestResult.failed,
                  message: 'DNSTT bootstrap returned SERVFAIL',
                ),
              );
            } else if (rcode == 5) {
              completer.complete(
                DnsttTestResult(
                  server: server,
                  result: TestResult.failed,
                  message: 'DNSTT bootstrap query was refused',
                ),
              );
            } else {
              completer.complete(
                DnsttTestResult(
                  server: server,
                  result: TestResult.failed,
                  message: 'DNSTT bootstrap failed (RCODE: $rcode)',
                ),
              );
            }
          } else {
            if (rcode == 0) {
              debugPrint(
                'DnsTest udp resolver-success resolver=${server.displayName} '
                'latency=${stopwatch.elapsedMilliseconds}ms',
              );
              completer.complete(
                DnsttTestResult(
                  server: server,
                  result: TestResult.success,
                  message: 'Resolver answered DNS',
                  latency: stopwatch.elapsed,
                ),
              );
            } else {
              debugPrint(
                'DnsTest udp failed resolver=${server.displayName} '
                'rcode=$rcode',
              );
              completer.complete(
                DnsttTestResult(
                  server: server,
                  result: TestResult.failed,
                  message: 'Resolver returned DNS error (RCODE: $rcode)',
                ),
              );
            }
          }
        }
      });

      final result = await completer.future;
      socket.close();
      return result;
    } on SocketException catch (e) {
      stopwatch.stop();
      socket?.close();
      return DnsttTestResult(
        server: server,
        result: TestResult.failed,
        message: 'Socket error: ${e.message}',
      );
    } catch (e) {
      stopwatch.stop();
      socket?.close();
      return DnsttTestResult(
        server: server,
        result: TestResult.failed,
        message: 'Error: $e',
      );
    }
  }

  static Future<DnsttTestResult> _testDnsServerViaDoh(
    DnsServer server, {
    Duration timeout = testTimeout,
  }) async {
    final stopwatch = Stopwatch()..start();
    final client = HttpClient()..connectionTimeout = timeout;

    try {
      final uri = Uri.parse(server.address);
      if (!uri.hasScheme || (uri.scheme != 'https' && uri.scheme != 'http')) {
        stopwatch.stop();
        return DnsttTestResult(
          server: server,
          result: TestResult.failed,
          message: 'Invalid DoH URL',
        );
      }

      debugPrint('DnsTest doh resolver=${server.displayName} url=$uri');

      final query = _buildSimpleDnsQuery();
      final expectedTransactionId = _transactionIdFromWire(query);
      final request = await client.postUrl(uri).timeout(timeout);
      request.headers.set('Accept', 'application/dns-message');
      request.headers.set('Content-Type', 'application/dns-message');
      request.headers.set('User-Agent', '');
      request.contentLength = query.length;
      request.add(query);

      final response = await request.close().timeout(timeout);
      final bodyBuilder = BytesBuilder(copy: false);
      await for (final chunk in response.timeout(timeout)) {
        bodyBuilder.add(chunk);
      }
      final body = bodyBuilder.toBytes();

      if (response.statusCode != HttpStatus.ok) {
        debugPrint(
          'DnsTest doh failed resolver=${server.displayName} '
          'status=${response.statusCode} retry=get',
        );
        return _testDnsServerViaDohGet(
          server,
          timeout: timeout,
          stopwatch: stopwatch,
        );
      }

      final result = _parseResolverResponse(
        server: server,
        data: body,
        stopwatch: stopwatch,
        expectedTransactionId: expectedTransactionId,
      );
      debugPrint(
        'DnsTest doh ${result.result == TestResult.success ? 'success' : 'failed'} '
        'resolver=${server.displayName} '
        'latency=${result.latency?.inMilliseconds ?? '-'}ms '
        'message=${result.message}',
      );
      return result;
    } on TimeoutException {
      stopwatch.stop();
      return DnsttTestResult(
        server: server,
        result: TestResult.timeout,
        message: 'DoH query timed out',
      );
    } on SocketException catch (e) {
      stopwatch.stop();
      return DnsttTestResult(
        server: server,
        result: TestResult.failed,
        message: 'Socket error: ${e.message}',
      );
    } on HandshakeException catch (e) {
      stopwatch.stop();
      return DnsttTestResult(
        server: server,
        result: TestResult.failed,
        message: 'TLS handshake failed: $e',
      );
    } catch (e) {
      stopwatch.stop();
      return DnsttTestResult(
        server: server,
        result: TestResult.failed,
        message: 'Error: $e',
      );
    } finally {
      client.close(force: true);
    }
  }

  static Future<DnsttTestResult> _testDnsServerViaDohGet(
    DnsServer server, {
    required Duration timeout,
    Stopwatch? stopwatch,
  }) async {
    final activeStopwatch = stopwatch ?? (Stopwatch()..start());
    final client = HttpClient()..connectionTimeout = timeout;

    try {
      final baseUri = Uri.parse(server.address);
      final query = _buildSimpleDnsQuery();
      final expectedTransactionId = _transactionIdFromWire(query);
      final encodedQuery = base64UrlEncode(query).replaceAll('=', '');
      final uri = baseUri.replace(
        queryParameters: {...baseUri.queryParameters, 'dns': encodedQuery},
      );

      debugPrint('DnsTest doh-get resolver=${server.displayName} url=$uri');

      final request = await client.getUrl(uri).timeout(timeout);
      request.headers.set('Accept', 'application/dns-message');
      request.headers.set('User-Agent', '');

      final response = await request.close().timeout(timeout);
      final bodyBuilder = BytesBuilder(copy: false);
      await for (final chunk in response.timeout(timeout)) {
        bodyBuilder.add(chunk);
      }
      final body = bodyBuilder.toBytes();

      if (response.statusCode != HttpStatus.ok) {
        activeStopwatch.stop();
        debugPrint(
          'DnsTest doh-get failed resolver=${server.displayName} '
          'status=${response.statusCode}',
        );
        return DnsttTestResult(
          server: server,
          result: TestResult.failed,
          message: 'DoH HTTP ${response.statusCode}',
        );
      }

      final result = _parseResolverResponse(
        server: server,
        data: body,
        stopwatch: activeStopwatch,
        expectedTransactionId: expectedTransactionId,
      );
      debugPrint(
        'DnsTest doh-get ${result.result == TestResult.success ? 'success' : 'failed'} '
        'resolver=${server.displayName} '
        'latency=${result.latency?.inMilliseconds ?? '-'}ms '
        'message=${result.message}',
      );
      return result;
    } on TimeoutException {
      activeStopwatch.stop();
      return DnsttTestResult(
        server: server,
        result: TestResult.timeout,
        message: 'DoH query timed out',
      );
    } on SocketException catch (e) {
      activeStopwatch.stop();
      return DnsttTestResult(
        server: server,
        result: TestResult.failed,
        message: 'Socket error: ${e.message}',
      );
    } on HandshakeException catch (e) {
      activeStopwatch.stop();
      return DnsttTestResult(
        server: server,
        result: TestResult.failed,
        message: 'TLS handshake failed: $e',
      );
    } catch (e) {
      activeStopwatch.stop();
      return DnsttTestResult(
        server: server,
        result: TestResult.failed,
        message: 'Error: $e',
      );
    } finally {
      client.close(force: true);
    }
  }

  static Future<DnsttTestResult> _testDnsServerViaDot(
    DnsServer server, {
    Duration timeout = testTimeout,
  }) async {
    final stopwatch = Stopwatch()..start();
    SecureSocket? socket;

    try {
      final endpoint = _parseDotEndpoint(server.address);
      if (endpoint == null) {
        stopwatch.stop();
        return DnsttTestResult(
          server: server,
          result: TestResult.failed,
          message: 'Invalid DoT address',
        );
      }

      debugPrint(
        'DnsTest dot resolver=${server.displayName} '
        'host=${endpoint.host} port=${endpoint.port}',
      );

      socket = await SecureSocket.connect(
        endpoint.host,
        endpoint.port,
        timeout: timeout,
      );

      final query = _buildSimpleDnsQuery();
      final expectedTransactionId = _transactionIdFromWire(query);
      final framedQuery = BytesBuilder(copy: false)
        ..addByte((query.length >> 8) & 0xFF)
        ..addByte(query.length & 0xFF)
        ..add(query);

      socket.add(framedQuery.toBytes());
      await socket.flush();

      final response = await _readDotResponse(socket, timeout);
      final result = _parseResolverResponse(
        server: server,
        data: response,
        stopwatch: stopwatch,
        expectedTransactionId: expectedTransactionId,
      );
      debugPrint(
        'DnsTest dot ${result.result == TestResult.success ? 'success' : 'failed'} '
        'resolver=${server.displayName} '
        'latency=${result.latency?.inMilliseconds ?? '-'}ms '
        'message=${result.message}',
      );
      return result;
    } on TimeoutException {
      stopwatch.stop();
      return DnsttTestResult(
        server: server,
        result: TestResult.timeout,
        message: 'DoT query timed out',
      );
    } on SocketException catch (e) {
      stopwatch.stop();
      return DnsttTestResult(
        server: server,
        result: TestResult.failed,
        message: 'Socket error: ${e.message}',
      );
    } on HandshakeException catch (e) {
      stopwatch.stop();
      return DnsttTestResult(
        server: server,
        result: TestResult.failed,
        message: 'TLS handshake failed: $e',
      );
    } catch (e) {
      stopwatch.stop();
      return DnsttTestResult(
        server: server,
        result: TestResult.failed,
        message: 'Error: $e',
      );
    } finally {
      await socket?.close();
    }
  }

  static DnsttTestResult _parseResolverResponse({
    required DnsServer server,
    required Uint8List data,
    required Stopwatch stopwatch,
    required int expectedTransactionId,
  }) {
    stopwatch.stop();

    if (data.length < 12) {
      return DnsttTestResult(
        server: server,
        result: TestResult.failed,
        message: 'Invalid DNS response',
      );
    }

    if (_transactionIdFromWire(data) != expectedTransactionId) {
      return DnsttTestResult(
        server: server,
        result: TestResult.failed,
        message: 'Mismatched DNS transaction ID',
      );
    }

    if (_isTruncatedDnsResponse(data)) {
      return DnsttTestResult(
        server: server,
        result: TestResult.failed,
        message: 'Resolver response was truncated',
      );
    }

    final flags = data[2];
    final isResponse = (flags & 0x80) != 0;
    if (!isResponse) {
      return DnsttTestResult(
        server: server,
        result: TestResult.failed,
        message: 'Invalid DNS response',
      );
    }

    final rcode = data[3] & 0x0F;
    if (rcode == 0) {
      return DnsttTestResult(
        server: server,
        result: TestResult.success,
        message: 'Resolver answered DNS',
        latency: stopwatch.elapsed,
      );
    }

    return DnsttTestResult(
      server: server,
      result: TestResult.failed,
      message: 'Resolver returned DNS error (RCODE: $rcode)',
    );
  }

  static int _transactionIdFromWire(List<int> data) {
    if (data.length < 2) {
      return -1;
    }
    return (data[0] << 8) | data[1];
  }

  static bool _isTruncatedDnsResponse(List<int> data) =>
      data.length > 2 && (data[2] & 0x02) != 0;

  static ({String host, int port})? _parseDotEndpoint(String address) {
    final normalized = address.trim();
    if (normalized.isEmpty) {
      return null;
    }

    if (!normalized.contains(':')) {
      return (host: normalized, port: 853);
    }

    final lastColon = normalized.lastIndexOf(':');
    if (lastColon <= 0 || lastColon == normalized.length - 1) {
      return null;
    }

    final host = normalized.substring(0, lastColon);
    final port = int.tryParse(normalized.substring(lastColon + 1));
    if (host.isEmpty || port == null) {
      return null;
    }
    return (host: host, port: port);
  }

  static Future<Uint8List> _readDotResponse(
    SecureSocket socket,
    Duration timeout,
  ) async {
    final completer = Completer<Uint8List>();
    final buffer = BytesBuilder(copy: false);
    StreamSubscription<List<int>>? subscription;
    Timer? timer;
    int? expectedLength;

    void completeIfReady() {
      final bytes = buffer.toBytes();
      if (expectedLength == null && bytes.length >= 2) {
        expectedLength = (bytes[0] << 8) | bytes[1];
      }
      if (expectedLength != null &&
          bytes.length >= expectedLength! + 2 &&
          !completer.isCompleted) {
        timer?.cancel();
        subscription?.cancel();
        completer.complete(
          Uint8List.fromList(bytes.sublist(2, expectedLength! + 2)),
        );
      }
    }

    timer = Timer(timeout, () {
      if (!completer.isCompleted) {
        subscription?.cancel();
        completer.completeError(TimeoutException('DoT query timed out'));
      }
    });

    subscription = socket.listen(
      (chunk) {
        buffer.add(chunk);
        completeIfReady();
      },
      onError: (Object error, StackTrace stackTrace) {
        if (!completer.isCompleted) {
          timer?.cancel();
          completer.completeError(error, stackTrace);
        }
      },
      onDone: () {
        if (!completer.isCompleted) {
          timer?.cancel();
          completer.completeError(
            const SocketException('Connection closed before DNS response'),
          );
        }
      },
      cancelOnError: true,
    );

    final response = await completer.future;
    timer.cancel();
    return response;
  }

  /// Tests multiple DNS servers with DNSTT or Slipstream tunnel
  /// Returns true if completed, false if cancelled
  static Future<bool> testMultipleDnsServersAll(
    List<DnsServer> servers, {
    String? tunnelDomain,
    String? publicKey,
    String testUrl = 'https://api.ipify.org?format=json',
    int concurrency = 3, // Lower concurrency for real tunnel tests
    Duration timeout = const Duration(seconds: 20),
    Future<void> Function(DnsttTestResult)? onResult,
    bool Function()? shouldCancel,
    TransportType transportType = TransportType.dnstt,
    String congestionControl = 'dcubic',
    int keepAliveInterval = 400,
    bool gso = false,
  }) async {
    final queue = List<DnsServer>.from(servers);

    // For tunnel tests, use concurrency of 1 to avoid issues with multiple clients
    // and to provide immediate progress feedback
    final actualConcurrency = (tunnelDomain != null && publicKey != null)
        ? 1 // Test one at a time for real tunnel connections
        : concurrency;

    // Process servers one at a time for immediate progress updates
    if (actualConcurrency == 1) {
      for (final server in queue) {
        // Check for cancellation before each test
        if (shouldCancel?.call() == true) {
          return false;
        }

        final result = await testDnsServer(
          server,
          tunnelDomain: tunnelDomain,
          publicKey: publicKey,
          testUrl: testUrl,
          timeout: timeout,
          transportType: transportType,
          congestionControl: congestionControl,
          keepAliveInterval: keepAliveInterval,
          gso: gso,
        );

        // Call onResult immediately after each test
        await onResult?.call(result);
      }
      return true;
    }

    // For non-tunnel tests (basic DNS), use batch processing
    while (queue.isNotEmpty) {
      // Check for cancellation before each batch
      if (shouldCancel?.call() == true) {
        return false;
      }

      final batch = <Future<DnsttTestResult>>[];
      final batchSize = queue.length < actualConcurrency
          ? queue.length
          : actualConcurrency;

      for (int i = 0; i < batchSize; i++) {
        final server = queue.removeAt(0);
        batch.add(
          testDnsServer(
            server,
            tunnelDomain: tunnelDomain,
            publicKey: publicKey,
            testUrl: testUrl,
            timeout: timeout,
            transportType: transportType,
            congestionControl: congestionControl,
            keepAliveInterval: keepAliveInterval,
            gso: gso,
          ),
        );
      }

      // Wait for batch to complete
      final batchResults = await Future.wait(batch);
      for (final result in batchResults) {
        await onResult?.call(result);
      }
    }

    return true;
  }

  /// Tests multiple resolvers directly, without starting the tunnel.
  static Future<bool> testMultipleResolvers(
    List<DnsServer> servers, {
    int concurrency = 3,
    Duration timeout = testTimeout,
    Future<void> Function(DnsttTestResult)? onResult,
    bool Function()? shouldCancel,
  }) async {
    final queue = List<DnsServer>.from(servers);

    while (queue.isNotEmpty) {
      if (shouldCancel?.call() == true) {
        return false;
      }

      final batch = <Future<DnsttTestResult>>[];
      final batchSize = queue.length < concurrency ? queue.length : concurrency;

      for (int i = 0; i < batchSize; i++) {
        final server = queue.removeAt(0);
        batch.add(testResolver(server, timeout: timeout));
      }

      final results = await Future.wait(batch);
      for (final result in results) {
        await onResult?.call(result);
      }
    }

    return true;
  }

  /// Tests the tunnel connection by making an HTTP request through the SOCKS5 proxy
  /// Uses raw TCP SOCKS5 handshake for cross-platform compatibility
  static Future<TunnelTestResult> testTunnelConnection(
    String testUrl, {
    String proxyHost = '127.0.0.1',
    int proxyPort = 1080,
    Duration timeout = const Duration(seconds: 15),
  }) async {
    final stopwatch = Stopwatch()..start();
    final client = HttpClient();
    client.connectionTimeout = timeout;

    try {
      SocksTCPClient.assignToHttpClientWithSecureOptions(client, [
        ProxySettings(InternetAddress(proxyHost), proxyPort),
      ]);
      final request = await client.getUrl(Uri.parse(testUrl)).timeout(timeout);
      request.headers.set('Connection', 'close');
      final response = await request.close().timeout(timeout);
      final responseBody = await response.transform(utf8.decoder).join();
      stopwatch.stop();
      client.close(force: true);

      return TunnelTestResult(
        result: response.statusCode >= 200 && response.statusCode < 400
            ? TestResult.success
            : TestResult.failed,
        message: 'HTTP ${response.statusCode}',
        latency: stopwatch.elapsed,
        statusCode: response.statusCode,
        responseBody: responseBody,
      );
    } on TimeoutException {
      client.close(force: true);
      stopwatch.stop();
      return TunnelTestResult(
        result: TestResult.timeout,
        message: 'Request timed out',
        latency: stopwatch.elapsed,
      );
    } on SocketException catch (e) {
      client.close(force: true);
      stopwatch.stop();
      return TunnelTestResult(
        result: TestResult.failed,
        message: 'Connection failed: ${e.message}',
        latency: stopwatch.elapsed,
      );
    } catch (e) {
      client.close(force: true);
      stopwatch.stop();
      return TunnelTestResult(
        result: TestResult.failed,
        message: 'Error: $e',
        latency: stopwatch.elapsed,
      );
    }
  }
}

/// Top-level function to run FFI test in a separate isolate
/// This must be a top-level function for compute() to work
int _runFfiTest(Map<String, dynamic> params) {
  final resolver = DnsServer(
    id: 'ffi-test-${params['resolverType']}',
    address: params['resolverValue'] as String,
    bootstrapAddress: params['dnsServer'] as String,
    resolverType: DnsResolverTypeWire.fromWireName(
      params['resolverType'] as String?,
    ),
  );
  final tunnelDomain = params['tunnelDomain'] as String;
  final publicKey = params['publicKey'] as String;
  final testUrl = params['testUrl'] as String;
  final timeoutMs = params['timeoutMs'] as int;

  try {
    // Load FFI library in this isolate
    final ffi = DnsttFfiService.instance;
    if (!ffi.isLoaded) {
      ffi.load();
    }

    // Run the test
    return ffi.testDnsServer(
      resolver: resolver,
      tunnelDomain: tunnelDomain,
      publicKey: publicKey,
      testUrl: testUrl,
      timeoutMs: timeoutMs,
    );
  } catch (e) {
    print('FFI test error in isolate: $e');
    return -1;
  }
}
