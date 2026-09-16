import "pe"
rule PKLITE_v1_00__v1_03 {
  strings:
    $a0 = { B8 ?? ?? BA ?? ?? 8C DB 03 D8 3B }

  condition:
    $a0 at pe.entry_point
}