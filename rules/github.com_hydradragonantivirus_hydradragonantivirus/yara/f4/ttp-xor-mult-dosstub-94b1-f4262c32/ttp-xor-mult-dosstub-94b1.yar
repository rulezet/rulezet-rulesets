rule TTP_XOR_MULT_DOSStub_94b1 {
  strings:
    $key_94b1 = { c0 d9 [2] b4 c1 [2] f3 c3 [2] b4 d2 [2] fa de [2] f6 d4 [2] e1 df [2] fa 91 [2] c7 }

  condition:
    any of them
}