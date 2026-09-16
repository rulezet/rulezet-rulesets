import "pe"
rule _NeoLite_v20_ {
  meta:
    description = "NeoLite v2.0"

  strings:
    $0 = { 8D 50 12 2B C9 B1 1E 8A 02 34 77 88 02 42 E2 F7 C8 }

  condition:
    $0 at pe.entry_point
}