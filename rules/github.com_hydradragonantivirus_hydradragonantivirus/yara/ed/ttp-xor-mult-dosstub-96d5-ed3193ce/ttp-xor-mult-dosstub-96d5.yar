rule TTP_XOR_MULT_DOSStub_96d5 {
  strings:
    $key_96d5 = { c2 bd [2] b6 a5 [2] f1 a7 [2] b6 b6 [2] f8 ba [2] f4 b0 [2] e3 bb [2] f8 f5 [2] c5 }

  condition:
    any of them
}