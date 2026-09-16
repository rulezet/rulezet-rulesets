rule TTP_XOR_MULT_DOSStub_4ca4 {
  strings:
    $key_4ca4 = { 18 cc [2] 6c d4 [2] 2b d6 [2] 6c c7 [2] 22 cb [2] 2e c1 [2] 39 ca [2] 22 84 [2] 1f }

  condition:
    any of them
}