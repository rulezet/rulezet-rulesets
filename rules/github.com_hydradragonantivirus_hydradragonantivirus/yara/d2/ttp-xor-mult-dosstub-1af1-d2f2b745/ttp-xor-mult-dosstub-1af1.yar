rule TTP_XOR_MULT_DOSStub_1af1 {
  strings:
    $key_1af1 = { 4e 99 [2] 3a 81 [2] 7d 83 [2] 3a 92 [2] 74 9e [2] 78 94 [2] 6f 9f [2] 74 d1 [2] 49 }

  condition:
    any of them
}