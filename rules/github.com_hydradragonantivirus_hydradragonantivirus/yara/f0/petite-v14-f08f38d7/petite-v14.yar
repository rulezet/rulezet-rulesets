import "pe"
rule _Petite_v14_ {
  meta:
    description = "Petite v1.4"

  strings:
    $0 = { B8 ?? ?? ?? ?? 66 9C 60 50 8B D8 03 00 68 ?? ?? ?? ?? 6A 00 }

  condition:
    $0 at pe.entry_point
}