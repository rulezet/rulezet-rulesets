rule TTP_XOR_MULT_DOSStub_65d7 {
  strings:
    $key_65d7 = { 31 bf [2] 45 a7 [2] 02 a5 [2] 45 b4 [2] 0b b8 [2] 07 b2 [2] 10 b9 [2] 0b f7 [2] 36 }

  condition:
    any of them
}