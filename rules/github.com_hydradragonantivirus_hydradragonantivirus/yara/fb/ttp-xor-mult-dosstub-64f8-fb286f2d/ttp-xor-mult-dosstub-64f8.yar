rule TTP_XOR_MULT_DOSStub_64f8 {
  strings:
    $key_64f8 = { 30 90 [2] 44 88 [2] 03 8a [2] 44 9b [2] 0a 97 [2] 06 9d [2] 11 96 [2] 0a d8 [2] 37 }

  condition:
    any of them
}