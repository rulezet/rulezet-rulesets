rule TTP_XOR_MULT_DOSStub_c3b2 {
  strings:
    $key_c3b2 = { 97 da [2] e3 c2 [2] a4 c0 [2] e3 d1 [2] ad dd [2] a1 d7 [2] b6 dc [2] ad 92 [2] 90 }

  condition:
    any of them
}