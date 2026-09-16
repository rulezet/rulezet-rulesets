rule TTP_XOR_MULT_DOSStub_c2d4 {
  strings:
    $key_c2d4 = { 96 bc [2] e2 a4 [2] a5 a6 [2] e2 b7 [2] ac bb [2] a0 b1 [2] b7 ba [2] ac f4 [2] 91 }

  condition:
    any of them
}