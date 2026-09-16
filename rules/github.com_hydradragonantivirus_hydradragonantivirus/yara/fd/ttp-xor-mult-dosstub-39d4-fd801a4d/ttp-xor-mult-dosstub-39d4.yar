rule TTP_XOR_MULT_DOSStub_39d4 {
  strings:
    $key_39d4 = { 6d bc [2] 19 a4 [2] 5e a6 [2] 19 b7 [2] 57 bb [2] 5b b1 [2] 4c ba [2] 57 f4 [2] 6a }

  condition:
    any of them
}