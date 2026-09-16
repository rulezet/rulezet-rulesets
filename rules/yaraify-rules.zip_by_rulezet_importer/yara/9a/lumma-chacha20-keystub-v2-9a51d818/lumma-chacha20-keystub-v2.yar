rule Lumma_ChaCha20_KeyStub_v2
{
  meta:
    author = "pebwalker"
    description = "Detects Lumma Stealer ChaCha20 key setup and stub"
    date = "2025-08-09"
    yarahub_uuid = "1a967f26-a3c0-4fd0-b6cf-fae4731c60ed"
    yarahub_license = "CC0 1.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp  = "TLP:WHITE"
    yarahub_reference_md5 = "0a0b4a3c4eb53ae6cd5c769de784eb8b"

  strings:
        $copy_stub = {
      B8 ?? ?? ?? ?? BF ?? ?? ?? ?? B9 08 00 00 00 96 F3 A5 96
      B8 ?? ?? ?? ?? BF ?? ?? ?? ?? 31 C9 96 F3 66 A5 96
    }

        $chacha_core_short = {
      81 EC 10 01 00 00               [0-64]
      B9 10 00 00 00                  [0-16]
      F3 A5                           [0-64]
      31 C9                           [0-16]
      F3 66 A5                      }

  condition:
    uint16(0) == 0x5A4D and
    uint32(uint32(0x3C)) == 0x00004550 and
    uint16(uint32(0x3C) + 4) == 0x014C and
    filesize < 50MB and
    $copy_stub and $chacha_core_short
}