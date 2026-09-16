rule TTP_XOR_MULT_DOSStub_2ad1 {
  strings:
    $key_2ad1 = { 7e b9 [2] 0a a1 [2] 4d a3 [2] 0a b2 [2] 44 be [2] 48 b4 [2] 5f bf [2] 44 f1 [2] 79 }

  condition:
    any of them
}