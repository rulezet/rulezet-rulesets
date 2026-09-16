import "pe"
rule _TMTPascal_v040_ {
  meta:
    description = "TMT-Pascal v0.40"

  strings:
    $0 = { 0E 1F 06 8C 06 ?? ?? 26 A1 ?? ?? A3 ?? ?? 8E C0 66 33 FF 66 33 C9 }

  condition:
    $0 at pe.entry_point
}