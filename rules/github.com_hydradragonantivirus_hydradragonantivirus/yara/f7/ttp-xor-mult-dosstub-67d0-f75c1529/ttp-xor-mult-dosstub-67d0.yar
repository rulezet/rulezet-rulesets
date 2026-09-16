rule TTP_XOR_MULT_DOSStub_67d0 {
  strings:
    $key_67d0 = { 33 b8 [2] 47 a0 [2] 00 a2 [2] 47 b3 [2] 09 bf [2] 05 b5 [2] 12 be [2] 09 f0 [2] 34 }

  condition:
    any of them
}