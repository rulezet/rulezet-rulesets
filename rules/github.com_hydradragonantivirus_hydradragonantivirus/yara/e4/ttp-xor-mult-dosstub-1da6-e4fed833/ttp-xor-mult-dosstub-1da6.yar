rule TTP_XOR_MULT_DOSStub_1da6 {
  strings:
    $key_1da6 = { 49 ce [2] 3d d6 [2] 7a d4 [2] 3d c5 [2] 73 c9 [2] 7f c3 [2] 68 c8 [2] 73 86 [2] 4e }

  condition:
    any of them
}