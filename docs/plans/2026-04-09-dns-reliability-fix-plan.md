# DNS Resolver Behavior Note

This note captures the intended resolver semantics for the DNS reliability work so runtime behavior stays aligned across Flutter, Kotlin, and Go.

## Resolver Roles

- Bootstrap resolver: used only to establish the DNSTT or Slipstream tunnel.
- App DNS resolver: used for device and app DNS queries after the tunnel is established.

## Mode Rules

- Non-strict DNS mode may use the direct network path for DNS queries.
- Non-strict direct DNS must use the selected app DNS resolver, not the bootstrap resolver, unless both were intentionally configured to be the same target.
- Strict DNS mode must keep DNS inside the tunnel.
- Strict DNS transport selection must follow the selected app resolver type:
  - UDP or local resolver targets use the tunneled TCP DNS path used by the app today.
  - DoH targets use tunneled DoH.
  - DoT targets use tunneled DoT.

## Direct Versus Tunneled DNS

- Direct DNS success means the selected resolver answered a DNS query on the network path available to Android outside the VPN.
- Tunnel bootstrap success means DNSTT or Slipstream was able to establish the tunnel through the bootstrap resolver.
- These outcomes are related, but they are not interchangeable and should be logged and surfaced separately in tests and UI.
