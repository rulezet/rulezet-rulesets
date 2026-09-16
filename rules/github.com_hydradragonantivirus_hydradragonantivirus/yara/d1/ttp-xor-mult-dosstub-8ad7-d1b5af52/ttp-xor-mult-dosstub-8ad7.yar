rule TTP_XOR_MULT_DOSStub_8ad7 {
  strings:
    $key_8ad7 = { de bf [2] aa a7 [2] ed a5 [2] aa b4 [2] e4 b8 [2] e8 b2 [2] ff b9 [2] e4 f7 [2] d9 }

  condition:
    any of them
}