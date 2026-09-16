rule TTP_XOR_MULT_DOSStub_45d7 {
  strings:
    $key_45d7 = { 11 bf [2] 65 a7 [2] 22 a5 [2] 65 b4 [2] 2b b8 [2] 27 b2 [2] 30 b9 [2] 2b f7 [2] 16 }

  condition:
    any of them
}