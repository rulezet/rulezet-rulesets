rule TTP_XOR_MULT_DOSStub_b5c6 {
  strings:
    $key_b5c6 = { e1 ae [2] 95 b6 [2] d2 b4 [2] 95 a5 [2] db a9 [2] d7 a3 [2] c0 a8 [2] db e6 [2] e6 }

  condition:
    any of them
}