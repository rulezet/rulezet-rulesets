rule TTP_XOR_MULT_DOSStub_94c5 {
  strings:
    $key_94c5 = { c0 ad [2] b4 b5 [2] f3 b7 [2] b4 a6 [2] fa aa [2] f6 a0 [2] e1 ab [2] fa e5 [2] c7 }

  condition:
    any of them
}