rule TTP_XOR_MULT_DOSStub_1397 {
  strings:
    $key_1397 = { 47 ff [2] 33 e7 [2] 74 e5 [2] 33 f4 [2] 7d f8 [2] 71 f2 [2] 66 f9 [2] 7d b7 [2] 40 }

  condition:
    any of them
}