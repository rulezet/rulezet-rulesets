rule TTP_XOR_MULT_DOSStub_39d6 {
  strings:
    $key_39d6 = { 6d be [2] 19 a6 [2] 5e a4 [2] 19 b5 [2] 57 b9 [2] 5b b3 [2] 4c b8 [2] 57 f6 [2] 6a }

  condition:
    any of them
}