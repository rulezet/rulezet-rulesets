import "pe"
rule Upack_v0_2_Beta____Dwing {
  strings:
    $a0 = { BE 88 01 ?? ?? AD 8B F8 95 A5 33 C0 33 }

  condition:
    $a0 at pe.entry_point
}