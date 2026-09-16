rule TTP_XOR_MULT_DOSStub_6248 {
  strings:
    $key_6248 = { 36 20 [2] 42 38 [2] 05 3a [2] 42 2b [2] 0c 27 [2] 00 2d [2] 17 26 [2] 0c 68 [2] 31 }

  condition:
    any of them
}