import "pe"
rule PE_PROTECT_0_9 {
  strings:
    $a0 = { E9 CF 00 00 00 0D 0A 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 }

  condition:
    $a0 at pe.entry_point
}