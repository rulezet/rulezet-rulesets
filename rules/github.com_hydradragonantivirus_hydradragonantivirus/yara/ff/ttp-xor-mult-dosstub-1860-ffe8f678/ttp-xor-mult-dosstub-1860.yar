rule TTP_XOR_MULT_DOSStub_1860 {
  strings:
    $key_1860 = { 4c 08 [2] 38 10 [2] 7f 12 [2] 38 03 [2] 76 0f [2] 7a 05 [2] 6d 0e [2] 76 40 [2] 4b }

  condition:
    any of them
}