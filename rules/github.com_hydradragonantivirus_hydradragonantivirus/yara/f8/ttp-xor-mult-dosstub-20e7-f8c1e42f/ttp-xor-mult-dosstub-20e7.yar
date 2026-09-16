rule TTP_XOR_MULT_DOSStub_20e7 {
  strings:
    $key_20e7 = { 74 8f [2] 00 97 [2] 47 95 [2] 00 84 [2] 4e 88 [2] 42 82 [2] 55 89 [2] 4e c7 [2] 73 }

  condition:
    any of them
}