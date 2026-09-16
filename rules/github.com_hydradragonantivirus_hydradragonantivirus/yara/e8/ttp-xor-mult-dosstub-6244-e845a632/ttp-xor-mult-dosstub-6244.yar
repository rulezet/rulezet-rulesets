rule TTP_XOR_MULT_DOSStub_6244 {
  strings:
    $key_6244 = { 36 2c [2] 42 34 [2] 05 36 [2] 42 27 [2] 0c 2b [2] 00 21 [2] 17 2a [2] 0c 64 [2] 31 }

  condition:
    any of them
}