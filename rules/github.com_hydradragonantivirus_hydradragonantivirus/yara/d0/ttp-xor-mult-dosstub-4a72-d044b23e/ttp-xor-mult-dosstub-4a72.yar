rule TTP_XOR_MULT_DOSStub_4a72 {
  strings:
    $key_4a72 = { 1e 1a [2] 6a 02 [2] 2d 00 [2] 6a 11 [2] 24 1d [2] 28 17 [2] 3f 1c [2] 24 52 [2] 19 }

  condition:
    any of them
}