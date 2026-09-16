rule TTP_XOR_MULT_DOSStub_a760 {
  strings:
    $key_a760 = { f3 08 [2] 87 10 [2] c0 12 [2] 87 03 [2] c9 0f [2] c5 05 [2] d2 0e [2] c9 40 [2] f4 }

  condition:
    any of them
}