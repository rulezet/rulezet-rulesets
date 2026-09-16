import "pe"
rule Trivial173_by_SMT_SMF {
  strings:
    $a0 = { EB ?? ?? 28 54 72 69 76 69 61 6C 31 37 33 20 62 79 20 53 4D 54 2F 53 4D 46 29 }

  condition:
    $a0 at pe.entry_point
}