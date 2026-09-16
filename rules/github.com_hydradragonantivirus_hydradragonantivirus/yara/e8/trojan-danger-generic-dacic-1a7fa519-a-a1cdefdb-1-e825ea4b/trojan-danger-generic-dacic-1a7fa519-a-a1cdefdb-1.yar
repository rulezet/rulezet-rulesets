rule Trojan_Danger_Generic_Dacic_1A7FA519_A_A1CDEFDB_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Generic.Dacic.1A7FA519.A.A1CDEFDB_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd8c7584ebef55705644f55bb800129ec0e1e8ef2bbd4f515e831743e77fc75c"

  strings:
    $s1 = ":shall be counted." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}