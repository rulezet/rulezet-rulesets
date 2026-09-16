import "pe"
rule ASProtect_V2_X_DLL____Alexey_Solodovnikov {
  strings:
    $a0 = { 60 E8 03 00 00 00 E9 ?? ?? 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ?? ?? ?? ?? 03 DD }

  condition:
    $a0 at pe.entry_point
}