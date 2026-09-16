rule TTP_XOR_MULT_DOSStub_7500 {
  strings:
    $key_7500 = { 21 68 [2] 55 70 [2] 12 72 [2] 55 63 [2] 1b 6f [2] 17 65 [2] 00 6e [2] 1b 20 [2] 26 }

  condition:
    any of them
}