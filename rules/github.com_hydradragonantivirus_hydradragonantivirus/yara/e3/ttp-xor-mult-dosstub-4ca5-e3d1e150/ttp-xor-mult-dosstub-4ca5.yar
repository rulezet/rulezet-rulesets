rule TTP_XOR_MULT_DOSStub_4ca5 {
  strings:
    $key_4ca5 = { 18 cd [2] 6c d5 [2] 2b d7 [2] 6c c6 [2] 22 ca [2] 2e c0 [2] 39 cb [2] 22 85 [2] 1f }

  condition:
    any of them
}