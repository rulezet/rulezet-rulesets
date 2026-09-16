rule Virus_Sysbot_Dump_Generic_Dialer_34ECF9D6_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.34ECF9D6_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f7fefb8453f66dbf8d852d5cb516ac391e8b91ca2da134ef82dbc4eddd48a3a"

  strings:
    $s1 = "Klip}SW(})" fullword ascii
    $s2 = "H!buBa%" fullword ascii
    $s3 = "'\"coCo" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}