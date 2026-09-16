rule TTP_XOR_MULT_DOSStub_46d0 {
  strings:
    $key_46d0 = { 12 b8 [2] 66 a0 [2] 21 a2 [2] 66 b3 [2] 28 bf [2] 24 b5 [2] 33 be [2] 28 f0 [2] 15 }

  condition:
    any of them
}