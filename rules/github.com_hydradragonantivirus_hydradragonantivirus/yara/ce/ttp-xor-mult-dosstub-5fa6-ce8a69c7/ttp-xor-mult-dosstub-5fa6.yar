rule TTP_XOR_MULT_DOSStub_5fa6 {
  strings:
    $key_5fa6 = { 0b ce [2] 7f d6 [2] 38 d4 [2] 7f c5 [2] 31 c9 [2] 3d c3 [2] 2a c8 [2] 31 86 [2] 0c }

  condition:
    any of them
}