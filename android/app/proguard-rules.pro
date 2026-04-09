# JSch resolves its crypto implementation classes by string name at runtime.
# Keep the full package to prevent release shrinking/obfuscation from breaking
# lookups such as com.jcraft.jsch.jce.Random.
-keep class com.jcraft.jsch.** { *; }

# JSch ships optional integrations for desktop agents/loggers/Kerberos/Unix sockets
# that are not present or used on Android. Suppress those references so R8 can
# shrink the library for release builds without failing on missing JVM-only types.
-dontwarn com.sun.jna.**
-dontwarn org.apache.logging.log4j.**
-dontwarn org.ietf.jgss.**
-dontwarn org.newsclub.net.unix.**
-dontwarn org.slf4j.**
