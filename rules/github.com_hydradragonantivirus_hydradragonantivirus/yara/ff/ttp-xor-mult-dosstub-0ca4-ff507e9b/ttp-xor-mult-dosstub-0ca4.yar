rule TTP_XOR_MULT_DOSStub_0ca4 {
  strings:
    $key_0ca4 = { 58 cc [2] 2c d4 [2] 6b d6 [2] 2c c7 [2] 62 cb [2] 6e c1 [2] 79 ca [2] 62 84 [2] 5f }

  condition:
    any of them
}