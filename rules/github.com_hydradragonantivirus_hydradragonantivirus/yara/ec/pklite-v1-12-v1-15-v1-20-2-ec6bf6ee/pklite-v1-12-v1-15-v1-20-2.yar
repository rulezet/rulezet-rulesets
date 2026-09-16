import "pe"
rule PKLITE_v1_12__v1_15__v1_20__2_ {
  strings:
    $a0 = { B8 ?? ?? BA ?? ?? 3B C4 73 }

  condition:
    $a0 at pe.entry_point
}