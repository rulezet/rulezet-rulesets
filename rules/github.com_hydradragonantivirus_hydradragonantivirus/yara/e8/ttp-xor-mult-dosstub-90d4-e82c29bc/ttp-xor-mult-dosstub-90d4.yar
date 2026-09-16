rule TTP_XOR_MULT_DOSStub_90d4 {
  strings:
    $key_90d4 = { c4 bc [2] b0 a4 [2] f7 a6 [2] b0 b7 [2] fe bb [2] f2 b1 [2] e5 ba [2] fe f4 [2] c3 }

  condition:
    any of them
}