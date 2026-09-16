rule TTP_XOR_MULT_DOSStub_91d9 {
  strings:
    $key_91d9 = { c5 b1 [2] b1 a9 [2] f6 ab [2] b1 ba [2] ff b6 [2] f3 bc [2] e4 b7 [2] ff f9 [2] c2 }

  condition:
    any of them
}