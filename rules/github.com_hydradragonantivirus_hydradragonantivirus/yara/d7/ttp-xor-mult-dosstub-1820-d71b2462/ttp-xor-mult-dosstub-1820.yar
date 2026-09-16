rule TTP_XOR_MULT_DOSStub_1820 {
  strings:
    $key_1820 = { 4c 48 [2] 38 50 [2] 7f 52 [2] 38 43 [2] 76 4f [2] 7a 45 [2] 6d 4e [2] 76 00 [2] 4b }

  condition:
    any of them
}