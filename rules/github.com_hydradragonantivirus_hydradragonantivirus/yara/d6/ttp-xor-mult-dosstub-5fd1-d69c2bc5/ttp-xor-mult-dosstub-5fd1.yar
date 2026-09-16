rule TTP_XOR_MULT_DOSStub_5fd1 {
  strings:
    $key_5fd1 = { 0b b9 [2] 7f a1 [2] 38 a3 [2] 7f b2 [2] 31 be [2] 3d b4 [2] 2a bf [2] 31 f1 [2] 0c }

  condition:
    any of them
}