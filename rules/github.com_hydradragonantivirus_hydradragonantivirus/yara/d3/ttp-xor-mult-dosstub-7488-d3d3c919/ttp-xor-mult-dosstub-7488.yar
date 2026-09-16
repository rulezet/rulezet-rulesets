rule TTP_XOR_MULT_DOSStub_7488 {
  strings:
    $key_7488 = { 20 e0 [2] 54 f8 [2] 13 fa [2] 54 eb [2] 1a e7 [2] 16 ed [2] 01 e6 [2] 1a a8 [2] 27 }

  condition:
    any of them
}