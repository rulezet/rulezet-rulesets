rule TTP_XOR_MULT_DOSStub_60c3 {
  strings:
    $key_60c3 = { 34 ab [2] 40 b3 [2] 07 b1 [2] 40 a0 [2] 0e ac [2] 02 a6 [2] 15 ad [2] 0e e3 [2] 33 }

  condition:
    any of them
}