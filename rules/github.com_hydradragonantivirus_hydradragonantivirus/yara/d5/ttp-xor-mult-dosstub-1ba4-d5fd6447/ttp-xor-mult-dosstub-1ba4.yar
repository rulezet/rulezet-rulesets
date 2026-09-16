rule TTP_XOR_MULT_DOSStub_1ba4 {
  strings:
    $key_1ba4 = { 4f cc [2] 3b d4 [2] 7c d6 [2] 3b c7 [2] 75 cb [2] 79 c1 [2] 6e ca [2] 75 84 [2] 48 }

  condition:
    any of them
}