rule TTP_XOR_MULT_DOSStub_1ca6 {
  strings:
    $key_1ca6 = { 48 ce [2] 3c d6 [2] 7b d4 [2] 3c c5 [2] 72 c9 [2] 7e c3 [2] 69 c8 [2] 72 86 [2] 4f }

  condition:
    any of them
}