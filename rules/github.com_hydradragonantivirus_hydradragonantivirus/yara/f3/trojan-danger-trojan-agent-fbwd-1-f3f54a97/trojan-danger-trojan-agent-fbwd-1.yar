rule Trojan_Danger_Trojan_Agent_FBWD_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.Agent.FBWD_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78bc8b60d656ef6c2c48660eed7f443a1cd2179066369f0e94c09850c78bf1ea"

  strings:
    $s1 = ":What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}