rule TTP_XOR_MULT_DOSStub_a727 {
  strings:
    $key_a727 = { f3 4f [2] 87 57 [2] c0 55 [2] 87 44 [2] c9 48 [2] c5 42 [2] d2 49 [2] c9 07 [2] f4 }

  condition:
    any of them
}