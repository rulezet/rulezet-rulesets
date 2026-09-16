rule TTP_XOR_MULT_DOSStub_09d7 {
  strings:
    $key_09d7 = { 5d bf [2] 29 a7 [2] 6e a5 [2] 29 b4 [2] 67 b8 [2] 6b b2 [2] 7c b9 [2] 67 f7 [2] 5a }

  condition:
    any of them
}