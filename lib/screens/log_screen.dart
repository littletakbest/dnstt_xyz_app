import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../providers/app_state.dart';

class LogScreen extends StatelessWidget {
  const LogScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Logs'),
        actions: [
          Consumer<AppState>(
            builder: (context, state, _) {
              return IconButton(
                tooltip: 'Clear logs',
                onPressed: state.logs.isEmpty
                    ? null
                    : () {
                        state.clearLogs();
                        ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(content: Text('Logs cleared')),
                        );
                      },
                icon: const Icon(Icons.delete_outline),
              );
            },
          ),
        ],
      ),
      body: Consumer<AppState>(
        builder: (context, state, _) {
          if (state.logs.isEmpty) {
            return Center(
              child: Padding(
                padding: const EdgeInsets.all(24),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(
                      Icons.receipt_long_outlined,
                      size: 56,
                      color: Colors.grey[400],
                    ),
                    const SizedBox(height: 12),
                    Text(
                      'No logs yet',
                      style: Theme.of(context).textTheme.titleMedium,
                    ),
                    const SizedBox(height: 8),
                    Text(
                      'Connection activity will appear here during this app session.',
                      style: TextStyle(color: Colors.grey[600]),
                      textAlign: TextAlign.center,
                    ),
                  ],
                ),
              ),
            );
          }

          final logs = state.logs.reversed.toList(growable: false);
          return ListView.separated(
            padding: const EdgeInsets.all(16),
            itemCount: logs.length,
            separatorBuilder: (_, _) => const SizedBox(height: 10),
            itemBuilder: (context, index) {
              final entry = logs[index];
              return Card(
                child: ListTile(
                  leading: const Icon(Icons.article_outlined),
                  title: Text(entry.message),
                  subtitle: Text(entry.timestampLabel),
                ),
              );
            },
          );
        },
      ),
    );
  }
}
