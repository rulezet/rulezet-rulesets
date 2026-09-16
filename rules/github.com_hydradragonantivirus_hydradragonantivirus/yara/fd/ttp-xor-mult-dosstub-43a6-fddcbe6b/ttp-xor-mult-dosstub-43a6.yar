rule TTP_XOR_MULT_DOSStub_43a6 {
  strings:
    $key_43a6 = { 17 ce [2] 63 d6 [2] 24 d4 [2] 63 c5 [2] 2d c9 [2] 21 c3 [2] 36 c8 [2] 2d 86 [2] 10 }

  condition:
    any of them
}