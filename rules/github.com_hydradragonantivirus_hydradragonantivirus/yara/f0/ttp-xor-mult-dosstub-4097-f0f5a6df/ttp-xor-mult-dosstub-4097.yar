rule TTP_XOR_MULT_DOSStub_4097 {
  strings:
    $key_4097 = { 14 ff [2] 60 e7 [2] 27 e5 [2] 60 f4 [2] 2e f8 [2] 22 f2 [2] 35 f9 [2] 2e b7 [2] 13 }

  condition:
    any of them
}