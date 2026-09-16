rule TTP_XOR_MULT_DOSStub_18e7 {
  strings:
    $key_18e7 = { 4c 8f [2] 38 97 [2] 7f 95 [2] 38 84 [2] 76 88 [2] 7a 82 [2] 6d 89 [2] 76 c7 [2] 4b }

  condition:
    any of them
}