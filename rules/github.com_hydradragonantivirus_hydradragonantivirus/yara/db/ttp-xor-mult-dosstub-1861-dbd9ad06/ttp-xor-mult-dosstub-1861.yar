rule TTP_XOR_MULT_DOSStub_1861 {
  strings:
    $key_1861 = { 4c 09 [2] 38 11 [2] 7f 13 [2] 38 02 [2] 76 0e [2] 7a 04 [2] 6d 0f [2] 76 41 [2] 4b }

  condition:
    any of them
}