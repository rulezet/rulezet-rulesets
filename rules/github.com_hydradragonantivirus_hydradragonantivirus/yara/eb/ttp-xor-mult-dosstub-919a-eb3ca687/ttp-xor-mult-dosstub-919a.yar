rule TTP_XOR_MULT_DOSStub_919a {
  strings:
    $key_919a = { c5 f2 [2] b1 ea [2] f6 e8 [2] b1 f9 [2] ff f5 [2] f3 ff [2] e4 f4 [2] ff ba [2] c2 }

  condition:
    any of them
}