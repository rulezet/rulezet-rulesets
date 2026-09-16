rule TTP_XOR_MULT_DOSStub_1770 {
  strings:
    $key_1770 = { 43 18 [2] 37 00 [2] 70 02 [2] 37 13 [2] 79 1f [2] 75 15 [2] 62 1e [2] 79 50 [2] 44 }

  condition:
    any of them
}