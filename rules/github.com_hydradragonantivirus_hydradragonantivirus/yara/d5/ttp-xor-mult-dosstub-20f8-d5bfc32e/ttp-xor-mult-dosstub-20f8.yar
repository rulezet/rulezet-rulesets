rule TTP_XOR_MULT_DOSStub_20f8 {
  strings:
    $key_20f8 = { 74 90 [2] 00 88 [2] 47 8a [2] 00 9b [2] 4e 97 [2] 42 9d [2] 55 96 [2] 4e d8 [2] 73 }

  condition:
    any of them
}