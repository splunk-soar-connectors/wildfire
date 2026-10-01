**Unreleased**

* Migrated the WildFire connector to Splunk SOAR SDK 4.1.2 while preserving the existing configuration and explicit API-key request behavior.
* Requires Splunk SOAR 7.0.0 or later because this release uses Splunk SOAR SDK 4.1.2.
* Implemented the existing connectivity, URL reputation, report retrieval, sample, PCAP, report download, file detonation, and URL detonation actions in the SDK application structure.
* Preserved legacy-compatible action names, messages, result tables, stable datapaths, summaries, and Vault file metadata.
* Preserved raw WildFire MAEC runtime data while publishing only stable MAEC package and object datapaths; dynamic observable-object keys remain available in action results.
* Added SDK-native report widgets for file detonation, URL detonation, and report retrieval.
* Packaged the existing connectivity PDF probe and hardened report rendering when WildFire omits optional report sections.
