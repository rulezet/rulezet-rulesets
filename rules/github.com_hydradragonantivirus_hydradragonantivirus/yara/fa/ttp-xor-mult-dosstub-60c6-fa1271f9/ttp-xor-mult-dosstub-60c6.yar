rule TTP_XOR_MULT_DOSStub_60c6 {
  strings:
    $key_60c6 = { 34 ae [2] 40 b6 [2] 07 b4 [2] 40 a5 [2] 0e a9 [2] 02 a3 [2] 15 a8 [2] 0e e6 [2] 33 }

  condition:
    any of them
}