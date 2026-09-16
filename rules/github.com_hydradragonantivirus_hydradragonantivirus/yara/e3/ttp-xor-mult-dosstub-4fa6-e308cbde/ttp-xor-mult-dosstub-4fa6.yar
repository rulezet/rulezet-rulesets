rule TTP_XOR_MULT_DOSStub_4fa6 {
  strings:
    $key_4fa6 = { 1b ce [2] 6f d6 [2] 28 d4 [2] 6f c5 [2] 21 c9 [2] 2d c3 [2] 3a c8 [2] 21 86 [2] 1c }

  condition:
    any of them
}