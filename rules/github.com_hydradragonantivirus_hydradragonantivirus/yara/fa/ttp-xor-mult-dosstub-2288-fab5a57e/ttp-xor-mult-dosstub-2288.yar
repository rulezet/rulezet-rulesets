rule TTP_XOR_MULT_DOSStub_2288 {
  strings:
    $key_2288 = { 76 e0 [2] 02 f8 [2] 45 fa [2] 02 eb [2] 4c e7 [2] 40 ed [2] 57 e6 [2] 4c a8 [2] 71 }

  condition:
    any of them
}