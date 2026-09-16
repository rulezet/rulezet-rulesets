rule TTP_XOR_MULT_DOSStub_6aa6 {
  strings:
    $key_6aa6 = { 3e ce [2] 4a d6 [2] 0d d4 [2] 4a c5 [2] 04 c9 [2] 08 c3 [2] 1f c8 [2] 04 86 [2] 39 }

  condition:
    any of them
}