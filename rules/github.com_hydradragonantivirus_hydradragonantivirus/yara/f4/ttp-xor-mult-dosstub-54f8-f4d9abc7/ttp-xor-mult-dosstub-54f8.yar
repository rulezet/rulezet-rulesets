rule TTP_XOR_MULT_DOSStub_54f8 {
  strings:
    $key_54f8 = { 00 90 [2] 74 88 [2] 33 8a [2] 74 9b [2] 3a 97 [2] 36 9d [2] 21 96 [2] 3a d8 [2] 07 }

  condition:
    any of them
}