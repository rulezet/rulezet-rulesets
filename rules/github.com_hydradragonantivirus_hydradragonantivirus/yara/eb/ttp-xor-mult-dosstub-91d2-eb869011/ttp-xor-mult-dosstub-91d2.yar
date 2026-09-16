rule TTP_XOR_MULT_DOSStub_91d2 {
  strings:
    $key_91d2 = { c5 ba [2] b1 a2 [2] f6 a0 [2] b1 b1 [2] ff bd [2] f3 b7 [2] e4 bc [2] ff f2 [2] c2 }

  condition:
    any of them
}