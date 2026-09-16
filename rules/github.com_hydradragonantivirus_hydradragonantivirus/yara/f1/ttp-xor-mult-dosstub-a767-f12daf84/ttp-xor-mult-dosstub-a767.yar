rule TTP_XOR_MULT_DOSStub_a767 {
  strings:
    $key_a767 = { f3 0f [2] 87 17 [2] c0 15 [2] 87 04 [2] c9 08 [2] c5 02 [2] d2 09 [2] c9 47 [2] f4 }

  condition:
    any of them
}