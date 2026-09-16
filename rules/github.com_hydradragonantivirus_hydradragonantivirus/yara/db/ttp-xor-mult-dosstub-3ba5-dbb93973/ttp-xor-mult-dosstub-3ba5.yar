rule TTP_XOR_MULT_DOSStub_3ba5 {
  strings:
    $key_3ba5 = { 6f cd [2] 1b d5 [2] 5c d7 [2] 1b c6 [2] 55 ca [2] 59 c0 [2] 4e cb [2] 55 85 [2] 68 }

  condition:
    any of them
}