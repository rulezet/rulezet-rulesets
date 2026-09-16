import "pe"
rule BopCrypt_v1_0 {
  strings:
    $a0 = { 60 BD ?? ?? ?? ?? E8 ?? ?? 00 00 }

  condition:
    $a0 at pe.entry_point
}