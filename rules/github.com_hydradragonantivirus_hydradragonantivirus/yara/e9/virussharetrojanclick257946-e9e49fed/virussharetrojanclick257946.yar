rule VirusShareTrojanClick257946 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanClick257946.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee0cbfb59adcc27d06170dc56f46bf2566b41736f853c0912a7c88a46e829784"

  strings:
    $s1 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Internet Explorer\\Main\\Start Page" fullword wide
    $s2 = "Wanda software company" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}