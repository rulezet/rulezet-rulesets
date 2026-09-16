rule TTP_XOR_MULT_DOSStub_86d9 {
  strings:
    $key_86d9 = { d2 b1 [2] a6 a9 [2] e1 ab [2] a6 ba [2] e8 b6 [2] e4 bc [2] f3 b7 [2] e8 f9 [2] d5 }

  condition:
    any of them
}