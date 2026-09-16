rule TTP_XOR_MULT_DOSStub_32e7 {
  strings:
    $key_32e7 = { 66 8f [2] 12 97 [2] 55 95 [2] 12 84 [2] 5c 88 [2] 50 82 [2] 47 89 [2] 5c c7 [2] 61 }

  condition:
    any of them
}