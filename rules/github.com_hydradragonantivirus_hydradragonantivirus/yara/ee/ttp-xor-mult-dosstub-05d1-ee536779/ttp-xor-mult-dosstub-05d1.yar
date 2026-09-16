rule TTP_XOR_MULT_DOSStub_05d1 {
  strings:
    $key_05d1 = { 51 b9 [2] 25 a1 [2] 62 a3 [2] 25 b2 [2] 6b be [2] 67 b4 [2] 70 bf [2] 6b f1 [2] 56 }

  condition:
    any of them
}