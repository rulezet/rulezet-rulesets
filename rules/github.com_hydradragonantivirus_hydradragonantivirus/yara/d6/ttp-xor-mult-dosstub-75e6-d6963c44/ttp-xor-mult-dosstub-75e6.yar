rule TTP_XOR_MULT_DOSStub_75e6 {
  strings:
    $key_75e6 = { 21 8e [2] 55 96 [2] 12 94 [2] 55 85 [2] 1b 89 [2] 17 83 [2] 00 88 [2] 1b c6 [2] 26 }

  condition:
    any of them
}