import "pe"
rule Vx__VCL__encrypted_ {
  strings:
    $a0 = { 01 B9 ?? ?? 81 34 ?? ?? 46 46 E2 F8 C3 }
    $a1 = { 01 B9 ?? ?? 81 35 ?? ?? 47 47 E2 F8 C3 }

  condition:
    $a0 at pe.entry_point or $a1 at pe.entry_point
}