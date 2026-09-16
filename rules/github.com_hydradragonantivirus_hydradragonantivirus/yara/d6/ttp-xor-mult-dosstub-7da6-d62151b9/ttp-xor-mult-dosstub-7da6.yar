rule TTP_XOR_MULT_DOSStub_7da6 {
  strings:
    $key_7da6 = { 29 ce [2] 5d d6 [2] 1a d4 [2] 5d c5 [2] 13 c9 [2] 1f c3 [2] 08 c8 [2] 13 86 [2] 2e }

  condition:
    any of them
}