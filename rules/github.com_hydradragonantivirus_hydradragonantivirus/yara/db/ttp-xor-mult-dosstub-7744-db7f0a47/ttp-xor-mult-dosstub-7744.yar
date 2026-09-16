rule TTP_XOR_MULT_DOSStub_7744 {
  strings:
    $key_7744 = { 23 2c [2] 57 34 [2] 10 36 [2] 57 27 [2] 19 2b [2] 15 21 [2] 02 2a [2] 19 64 [2] 24 }

  condition:
    any of them
}