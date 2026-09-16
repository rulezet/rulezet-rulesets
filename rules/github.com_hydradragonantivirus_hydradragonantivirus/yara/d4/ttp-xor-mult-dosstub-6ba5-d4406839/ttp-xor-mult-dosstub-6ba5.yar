rule TTP_XOR_MULT_DOSStub_6ba5 {
  strings:
    $key_6ba5 = { 3f cd [2] 4b d5 [2] 0c d7 [2] 4b c6 [2] 05 ca [2] 09 c0 [2] 1e cb [2] 05 85 [2] 38 }

  condition:
    any of them
}