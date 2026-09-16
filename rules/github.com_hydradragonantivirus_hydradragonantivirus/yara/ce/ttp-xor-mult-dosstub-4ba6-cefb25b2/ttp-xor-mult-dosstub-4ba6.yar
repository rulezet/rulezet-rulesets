rule TTP_XOR_MULT_DOSStub_4ba6 {
  strings:
    $key_4ba6 = { 1f ce [2] 6b d6 [2] 2c d4 [2] 6b c5 [2] 25 c9 [2] 29 c3 [2] 3e c8 [2] 25 86 [2] 18 }

  condition:
    any of them
}