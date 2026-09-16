rule TTP_XOR_MULT_DOSStub_c3b4 {
  strings:
    $key_c3b4 = { 97 dc [2] e3 c4 [2] a4 c6 [2] e3 d7 [2] ad db [2] a1 d1 [2] b6 da [2] ad 94 [2] 90 }

  condition:
    any of them
}