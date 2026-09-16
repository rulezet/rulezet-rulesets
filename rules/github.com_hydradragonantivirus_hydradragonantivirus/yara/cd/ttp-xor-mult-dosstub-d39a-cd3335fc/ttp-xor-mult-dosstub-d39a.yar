rule TTP_XOR_MULT_DOSStub_d39a {
  strings:
    $key_d39a = { 87 f2 [2] f3 ea [2] b4 e8 [2] f3 f9 [2] bd f5 [2] b1 ff [2] a6 f4 [2] bd ba [2] 80 }

  condition:
    any of them
}