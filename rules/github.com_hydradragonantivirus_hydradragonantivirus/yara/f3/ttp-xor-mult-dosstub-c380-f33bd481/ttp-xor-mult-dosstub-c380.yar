rule TTP_XOR_MULT_DOSStub_c380 {
  strings:
    $key_c380 = { 97 e8 [2] e3 f0 [2] a4 f2 [2] e3 e3 [2] ad ef [2] a1 e5 [2] b6 ee [2] ad a0 [2] 90 }

  condition:
    any of them
}