rule TTP_XOR_MULT_DOSStub_eba6 {
  strings:
    $key_eba6 = { bf ce [2] cb d6 [2] 8c d4 [2] cb c5 [2] 85 c9 [2] 89 c3 [2] 9e c8 [2] 85 86 [2] b8 }

  condition:
    any of them
}