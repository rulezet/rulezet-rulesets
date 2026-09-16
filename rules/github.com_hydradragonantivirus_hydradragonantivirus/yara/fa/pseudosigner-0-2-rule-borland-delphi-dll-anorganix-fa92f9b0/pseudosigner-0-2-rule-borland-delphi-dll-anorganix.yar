import "pe"
rule __PseudoSigner_0_2_rule__Borland_Delphi_DLL______Anorganix {
  strings:
    $a0 = { 55 8B EC 83 C4 B4 B8 90 90 90 90 E8 00 00 00 00 E8 00 00 00 00 8D 40 00 }

  condition:
    $a0 at pe.entry_point
}