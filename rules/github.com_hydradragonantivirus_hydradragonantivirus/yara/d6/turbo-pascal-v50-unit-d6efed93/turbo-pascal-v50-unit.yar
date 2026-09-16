import "pe"
rule _Turbo_Pascal_v50_Unit_ {
  meta:
    description = "Turbo Pascal v5.0 Unit"

  strings:
    $0 = { 54 50 55 35 00 }

  condition:
    $0 at pe.entry_point
}