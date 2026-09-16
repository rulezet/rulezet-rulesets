rule TTP_XOR_MULT_DOSStub_7dd6 {
  strings:
    $key_7dd6 = { 29 be [2] 5d a6 [2] 1a a4 [2] 5d b5 [2] 13 b9 [2] 1f b3 [2] 08 b8 [2] 13 f6 [2] 2e }

  condition:
    any of them
}