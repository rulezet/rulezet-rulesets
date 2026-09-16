import "pe"
rule MAL_SQLMaggie_dll_export {
  meta:
    description   = "Matches DLL export found in SQLMaggie backdoor used by China-nexus threat actor WIP19."
    last_modified = "2024-01-07"
    author        = "@petermstewart"
    DaysofYara    = "7/100"
    ref           = "https://www.sentinelone.com/labs/wip19-espionage-new-chinese-apt-targets-it-service-providers-and-telcos-with-signed-malware/"
    sha256        = "f29a311d62c54bbb01f675db9864f4ab0b3483e6cfdd15a745d4943029dcdf14"

  condition:
    uint16(0) == 0x5a4d and
    pe.number_of_exports == 1 and
    pe.export_details[0].name == "maggie"
}