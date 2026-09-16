import "pe"
rule Inno_Setup_Module_ren {
  strings:
    $a0 = { 49 6E 6E 6F 53 65 74 75 70 4C 64 72 57 69 6E 64 6F 77 00 00 53 54 41 54 49 43 }

  condition:
    $a0 at pe.entry_point
}