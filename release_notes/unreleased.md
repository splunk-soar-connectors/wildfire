**Unreleased**

* Migrated the WildFire connector to Splunk SOAR SDK 4.1.2 while preserving the existing configuration and explicit API-key request behavior.
* Implemented the existing connectivity, URL reputation, report retrieval, sample, PCAP, report download, file detonation, and URL detonation actions in the SDK application structure.
* Preserved legacy-compatible action names, messages, result tables, datapaths, summaries, and Vault file metadata.
* Added SDK-native report widgets for file detonation, URL detonation, and report retrieval.
* Packaged the existing connectivity PDF probe and hardened report rendering when WildFire omits optional report sections.
