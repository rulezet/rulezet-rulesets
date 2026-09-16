rule TTP_XOR_MULT_DOSStub_3dd6 {
  strings:
    $key_3dd6 = { 69 be [2] 1d a6 [2] 5a a4 [2] 1d b5 [2] 53 b9 [2] 5f b3 [2] 48 b8 [2] 53 f6 [2] 6e }

  condition:
    any of them
}