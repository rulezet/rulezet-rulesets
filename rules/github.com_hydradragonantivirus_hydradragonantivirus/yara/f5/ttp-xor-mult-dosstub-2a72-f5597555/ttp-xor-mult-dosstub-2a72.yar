rule TTP_XOR_MULT_DOSStub_2a72 {
  strings:
    $key_2a72 = { 7e 1a [2] 0a 02 [2] 4d 00 [2] 0a 11 [2] 44 1d [2] 48 17 [2] 5f 1c [2] 44 52 [2] 79 }

  condition:
    any of them
}