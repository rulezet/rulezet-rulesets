rule TTP_XOR_MULT_DOSStub_4dd6 {
  strings:
    $key_4dd6 = { 19 be [2] 6d a6 [2] 2a a4 [2] 6d b5 [2] 23 b9 [2] 2f b3 [2] 38 b8 [2] 23 f6 [2] 1e }

  condition:
    any of them
}