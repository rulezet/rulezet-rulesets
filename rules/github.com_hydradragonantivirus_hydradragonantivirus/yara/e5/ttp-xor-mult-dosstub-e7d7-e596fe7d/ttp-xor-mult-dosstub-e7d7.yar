rule TTP_XOR_MULT_DOSStub_e7d7 {
  strings:
    $key_e7d7 = { b3 bf [2] c7 a7 [2] 80 a5 [2] c7 b4 [2] 89 b8 [2] 85 b2 [2] 92 b9 [2] 89 f7 [2] b4 }

  condition:
    any of them
}