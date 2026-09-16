rule TTP_XOR_MULT_DOSStub_a4b2 {
  strings:
    $key_a4b2 = { f0 da [2] 84 c2 [2] c3 c0 [2] 84 d1 [2] ca dd [2] c6 d7 [2] d1 dc [2] ca 92 [2] f7 }

  condition:
    any of them
}