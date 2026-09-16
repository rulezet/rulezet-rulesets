rule TTP_XOR_MULT_DOSStub_1af7 {
  strings:
    $key_1af7 = { 4e 9f [2] 3a 87 [2] 7d 85 [2] 3a 94 [2] 74 98 [2] 78 92 [2] 6f 99 [2] 74 d7 [2] 49 }

  condition:
    any of them
}