rule TTP_XOR_MULT_DOSStub_2244 {
  strings:
    $key_2244 = { 76 2c [2] 02 34 [2] 45 36 [2] 02 27 [2] 4c 2b [2] 40 21 [2] 57 2a [2] 4c 64 [2] 71 }

  condition:
    any of them
}