rule TTP_XOR_MULT_DOSStub_6397 {
  strings:
    $key_6397 = { 37 ff [2] 43 e7 [2] 04 e5 [2] 43 f4 [2] 0d f8 [2] 01 f2 [2] 16 f9 [2] 0d b7 [2] 30 }

  condition:
    any of them
}