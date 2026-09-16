rule TTP_XOR_MULT_DOSStub_3bb6 {
  strings:
    $key_3bb6 = { 6f de [2] 1b c6 [2] 5c c4 [2] 1b d5 [2] 55 d9 [2] 59 d3 [2] 4e d8 [2] 55 96 [2] 68 }

  condition:
    any of them
}