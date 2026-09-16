rule TTP_XOR_MULT_DOSStub_62e7 {
  strings:
    $key_62e7 = { 36 8f [2] 42 97 [2] 05 95 [2] 42 84 [2] 0c 88 [2] 00 82 [2] 17 89 [2] 0c c7 [2] 31 }

  condition:
    any of them
}