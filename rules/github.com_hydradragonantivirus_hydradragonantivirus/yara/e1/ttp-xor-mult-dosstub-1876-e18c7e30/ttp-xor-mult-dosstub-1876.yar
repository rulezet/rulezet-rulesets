rule TTP_XOR_MULT_DOSStub_1876 {
  strings:
    $key_1876 = { 4c 1e [2] 38 06 [2] 7f 04 [2] 38 15 [2] 76 19 [2] 7a 13 [2] 6d 18 [2] 76 56 [2] 4b }

  condition:
    any of them
}