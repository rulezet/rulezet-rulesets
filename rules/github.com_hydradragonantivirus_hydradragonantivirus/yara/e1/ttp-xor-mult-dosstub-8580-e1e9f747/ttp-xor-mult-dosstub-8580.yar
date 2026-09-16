rule TTP_XOR_MULT_DOSStub_8580 {
  strings:
    $key_8580 = { d1 e8 [2] a5 f0 [2] e2 f2 [2] a5 e3 [2] eb ef [2] e7 e5 [2] f0 ee [2] eb a0 [2] d6 }

  condition:
    any of them
}