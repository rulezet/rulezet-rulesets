rule TTP_XOR_MULT_DOSStub_91b1 {
  strings:
    $key_91b1 = { c5 d9 [2] b1 c1 [2] f6 c3 [2] b1 d2 [2] ff de [2] f3 d4 [2] e4 df [2] ff 91 [2] c2 }

  condition:
    any of them
}