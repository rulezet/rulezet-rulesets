rule TTP_XOR_MULT_DOSStub_94c8 {
  strings:
    $key_94c8 = { c0 a0 [2] b4 b8 [2] f3 ba [2] b4 ab [2] fa a7 [2] f6 ad [2] e1 a6 [2] fa e8 [2] c7 }

  condition:
    any of them
}