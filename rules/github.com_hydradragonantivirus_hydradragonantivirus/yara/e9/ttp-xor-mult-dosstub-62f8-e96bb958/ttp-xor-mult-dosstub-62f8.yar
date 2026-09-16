rule TTP_XOR_MULT_DOSStub_62f8 {
  strings:
    $key_62f8 = { 36 90 [2] 42 88 [2] 05 8a [2] 42 9b [2] 0c 97 [2] 00 9d [2] 17 96 [2] 0c d8 [2] 31 }

  condition:
    any of them
}