rule TTP_XOR_MULT_DOSStub_e3d1 {
  strings:
    $key_e3d1 = { b7 b9 [2] c3 a1 [2] 84 a3 [2] c3 b2 [2] 8d be [2] 81 b4 [2] 96 bf [2] 8d f1 [2] b0 }

  condition:
    any of them
}