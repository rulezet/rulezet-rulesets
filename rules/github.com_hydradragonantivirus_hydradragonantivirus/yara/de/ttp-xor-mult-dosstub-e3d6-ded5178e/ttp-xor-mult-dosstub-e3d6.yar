rule TTP_XOR_MULT_DOSStub_e3d6 {
  strings:
    $key_e3d6 = { b7 be [2] c3 a6 [2] 84 a4 [2] c3 b5 [2] 8d b9 [2] 81 b3 [2] 96 b8 [2] 8d f6 [2] b0 }

  condition:
    any of them
}