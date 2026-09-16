import "pe"
rule Ding_Boy_s_PE_lock_Phantasm_v1_5b3 {
  strings:
    $a0 = { 9C 55 57 56 52 51 53 9C FA E8 00 00 00 00 5D 81 ED 5B 53 40 00 B0 }

  condition:
    $a0 at pe.entry_point
}