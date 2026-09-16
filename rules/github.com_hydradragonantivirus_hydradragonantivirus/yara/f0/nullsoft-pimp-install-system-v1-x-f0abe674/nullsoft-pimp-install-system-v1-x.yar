import "pe"
rule Nullsoft_PIMP_Install_System_v1_x {
  strings:
    $a0 = { 83 EC 5C 53 55 56 57 FF 15 ?? ?? ?? 00 }

  condition:
    $a0 at pe.entry_point
}