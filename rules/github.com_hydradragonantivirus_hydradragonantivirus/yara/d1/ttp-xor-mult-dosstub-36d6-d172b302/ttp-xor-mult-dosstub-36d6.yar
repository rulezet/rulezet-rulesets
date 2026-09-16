rule TTP_XOR_MULT_DOSStub_36d6 {
  strings:
    $key_36d6 = { 62 be [2] 16 a6 [2] 51 a4 [2] 16 b5 [2] 58 b9 [2] 54 b3 [2] 43 b8 [2] 58 f6 [2] 65 }

  condition:
    any of them
}