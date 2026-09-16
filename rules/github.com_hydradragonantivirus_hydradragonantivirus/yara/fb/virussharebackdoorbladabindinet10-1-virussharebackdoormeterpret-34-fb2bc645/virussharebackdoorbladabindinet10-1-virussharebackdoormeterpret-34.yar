import "pe"
rule _VirusShareBackDoorBladabindiNET10_1_VirusShareBackDoorMeterpret_34 {
  meta:
    description = "datamaliciousorder - from files VirusShareBackDoorBladabindiNET10_1.vir, VirusShareBackDoorMeterpreter216_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a4add1669f98ec6131aa854163d4263d0f209721a80d5eea95ad3e5fe95799f"
    hash2       = "24a74fe93a846bd7c217d93a1bfdac5b3f000a7a448fd761f7da629990f2aaa1"

  strings:
    $s1 = "System<sH" fullword ascii
    $s2 = "Count UK" fullword ascii
    $s3 = "Current `I" fullword ascii
    $s4 = "Current`2D" fullword ascii
    $s5 = "Count@kE" fullword ascii
    $s6 = "Current@LI" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "f9e81afd2870aaecd8ace36b2893b1d3" and (all of them)
    ) or (all of them)
}