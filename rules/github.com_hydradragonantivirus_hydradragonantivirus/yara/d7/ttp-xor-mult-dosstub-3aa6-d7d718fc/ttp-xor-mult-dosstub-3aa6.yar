rule TTP_XOR_MULT_DOSStub_3aa6 {
  strings:
    $key_3aa6 = { 6e ce [2] 1a d6 [2] 5d d4 [2] 1a c5 [2] 54 c9 [2] 58 c3 [2] 4f c8 [2] 54 86 [2] 69 }

  condition:
    any of them
}