rule TTP_XOR_MULT_DOSStub_e4d1 {
  strings:
    $key_e4d1 = { b0 b9 [2] c4 a1 [2] 83 a3 [2] c4 b2 [2] 8a be [2] 86 b4 [2] 91 bf [2] 8a f1 [2] b7 }

  condition:
    any of them
}