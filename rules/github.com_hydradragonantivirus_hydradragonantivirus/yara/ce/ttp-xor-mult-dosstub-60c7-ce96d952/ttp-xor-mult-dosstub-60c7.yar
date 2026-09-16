rule TTP_XOR_MULT_DOSStub_60c7 {
  strings:
    $key_60c7 = { 34 af [2] 40 b7 [2] 07 b5 [2] 40 a4 [2] 0e a8 [2] 02 a2 [2] 15 a9 [2] 0e e7 [2] 33 }

  condition:
    any of them
}