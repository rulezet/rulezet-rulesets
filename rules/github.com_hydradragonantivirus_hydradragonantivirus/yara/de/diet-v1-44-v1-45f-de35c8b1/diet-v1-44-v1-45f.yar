import "pe"
rule DIET_v1_44__v1_45f {
  strings:
    $a0 = { F8 9C 06 1E 57 56 52 51 53 50 0E FC 8C C8 BA ?? ?? 03 D0 52 }

  condition:
    $a0 at pe.entry_point
}