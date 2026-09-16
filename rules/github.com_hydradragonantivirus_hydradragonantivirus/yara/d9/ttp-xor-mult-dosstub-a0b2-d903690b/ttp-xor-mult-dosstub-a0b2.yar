rule TTP_XOR_MULT_DOSStub_a0b2 {
  strings:
    $key_a0b2 = { f4 da [2] 80 c2 [2] c7 c0 [2] 80 d1 [2] ce dd [2] c2 d7 [2] d5 dc [2] ce 92 [2] f3 }

  condition:
    any of them
}