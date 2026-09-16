rule TTP_XOR_MULT_DOSStub_a177 {
  strings:
    $key_a177 = { f5 1f [2] 81 07 [2] c6 05 [2] 81 14 [2] cf 18 [2] c3 12 [2] d4 19 [2] cf 57 [2] f2 }

  condition:
    any of them
}