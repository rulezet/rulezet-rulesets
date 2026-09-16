rule TTP_XOR_MULT_DOSStub_2bb6 {
  strings:
    $key_2bb6 = { 7f de [2] 0b c6 [2] 4c c4 [2] 0b d5 [2] 45 d9 [2] 49 d3 [2] 5e d8 [2] 45 96 [2] 78 }

  condition:
    any of them
}