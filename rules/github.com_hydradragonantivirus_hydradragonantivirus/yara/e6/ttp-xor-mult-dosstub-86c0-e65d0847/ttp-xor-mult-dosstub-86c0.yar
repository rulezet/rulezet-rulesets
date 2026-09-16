rule TTP_XOR_MULT_DOSStub_86c0 {
  strings:
    $key_86c0 = { d2 a8 [2] a6 b0 [2] e1 b2 [2] a6 a3 [2] e8 af [2] e4 a5 [2] f3 ae [2] e8 e0 [2] d5 }

  condition:
    any of them
}