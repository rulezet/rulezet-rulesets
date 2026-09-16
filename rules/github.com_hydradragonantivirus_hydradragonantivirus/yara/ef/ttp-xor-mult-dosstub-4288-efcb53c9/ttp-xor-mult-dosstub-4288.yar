rule TTP_XOR_MULT_DOSStub_4288 {
  strings:
    $key_4288 = { 16 e0 [2] 62 f8 [2] 25 fa [2] 62 eb [2] 2c e7 [2] 20 ed [2] 37 e6 [2] 2c a8 [2] 11 }

  condition:
    any of them
}