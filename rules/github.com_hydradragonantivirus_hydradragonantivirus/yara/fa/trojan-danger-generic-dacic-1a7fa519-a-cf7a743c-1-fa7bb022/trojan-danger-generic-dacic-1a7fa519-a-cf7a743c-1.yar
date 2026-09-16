rule Trojan_Danger_Generic_Dacic_1A7FA519_A_CF7A743C_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Generic.Dacic.1A7FA519.A.CF7A743C_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d29caec8b9d6a3e706748af0b42e7cce4fabf520d19c40b5c4ad3399b3743695"

  strings:
    $s1 = ".Oracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}