import "pe"
rule _EPack_1_4_lite__final____by_6aHguT {
  strings:
    $a0 = { 33 C0 8B C0 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 }

  condition:
    $a0 at pe.entry_point
}