rule TTP_XOR_MULT_DOSStub_28e7 {
  strings:
    $key_28e7 = { 7c 8f [2] 08 97 [2] 4f 95 [2] 08 84 [2] 46 88 [2] 4a 82 [2] 5d 89 [2] 46 c7 [2] 7b }

  condition:
    any of them
}