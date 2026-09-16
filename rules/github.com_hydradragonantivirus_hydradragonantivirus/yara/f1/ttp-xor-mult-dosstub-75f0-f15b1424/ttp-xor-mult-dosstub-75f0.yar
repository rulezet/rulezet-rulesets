rule TTP_XOR_MULT_DOSStub_75f0 {
  strings:
    $key_75f0 = { 21 98 [2] 55 80 [2] 12 82 [2] 55 93 [2] 1b 9f [2] 17 95 [2] 00 9e [2] 1b d0 [2] 26 }

  condition:
    any of them
}