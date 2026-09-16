rule TTP_XOR_MULT_DOSStub_79d7 {
  strings:
    $key_79d7 = { 2d bf [2] 59 a7 [2] 1e a5 [2] 59 b4 [2] 17 b8 [2] 1b b2 [2] 0c b9 [2] 17 f7 [2] 2a }

  condition:
    any of them
}