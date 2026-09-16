import "pe"
rule Nullsoft_PIMP_Install_System_v1_3x {
  strings:
    $a0 = { 55 8B EC 81 EC ?? ?? 00 00 56 57 6A ?? BE ?? ?? ?? ?? 59 8D BD }

  condition:
    $a0 at pe.entry_point
}