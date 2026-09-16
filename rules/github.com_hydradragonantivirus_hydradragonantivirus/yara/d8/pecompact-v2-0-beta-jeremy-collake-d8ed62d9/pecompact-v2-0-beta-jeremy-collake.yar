import "pe"
rule PECompact_v2_0_beta____Jeremy_Collake {
  strings:
    $a0 = { B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 }

  condition:
    $a0 at pe.entry_point
}