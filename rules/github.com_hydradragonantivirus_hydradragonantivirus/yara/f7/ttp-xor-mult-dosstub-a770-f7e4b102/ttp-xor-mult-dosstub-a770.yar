rule TTP_XOR_MULT_DOSStub_a770 {
  strings:
    $key_a770 = { f3 18 [2] 87 00 [2] c0 02 [2] 87 13 [2] c9 1f [2] c5 15 [2] d2 1e [2] c9 50 [2] f4 }

  condition:
    any of them
}