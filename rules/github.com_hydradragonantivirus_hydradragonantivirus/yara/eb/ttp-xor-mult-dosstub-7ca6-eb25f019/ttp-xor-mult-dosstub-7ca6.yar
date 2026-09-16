rule TTP_XOR_MULT_DOSStub_7ca6 {
  strings:
    $key_7ca6 = { 28 ce [2] 5c d6 [2] 1b d4 [2] 5c c5 [2] 12 c9 [2] 1e c3 [2] 09 c8 [2] 12 86 [2] 2f }

  condition:
    any of them
}