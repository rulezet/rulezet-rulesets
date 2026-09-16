rule TTP_XOR_MULT_DOSStub_75f1 {
  strings:
    $key_75f1 = { 21 99 [2] 55 81 [2] 12 83 [2] 55 92 [2] 1b 9e [2] 17 94 [2] 00 9f [2] 1b d1 [2] 26 }

  condition:
    any of them
}