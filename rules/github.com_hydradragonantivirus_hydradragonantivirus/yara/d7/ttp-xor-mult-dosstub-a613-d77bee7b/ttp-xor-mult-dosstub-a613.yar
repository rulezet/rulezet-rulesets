rule TTP_XOR_MULT_DOSStub_a613 {
  strings:
    $key_a613 = { f2 7b [2] 86 63 [2] c1 61 [2] 86 70 [2] c8 7c [2] c4 76 [2] d3 7d [2] c8 33 [2] f5 }

  condition:
    any of them
}