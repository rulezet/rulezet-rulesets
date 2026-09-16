rule TTP_XOR_MULT_DOSStub_91c5 {
  strings:
    $key_91c5 = { c5 ad [2] b1 b5 [2] f6 b7 [2] b1 a6 [2] ff aa [2] f3 a0 [2] e4 ab [2] ff e5 [2] c2 }

  condition:
    any of them
}