rule TTP_XOR_MULT_DOSStub_7a44 {
  strings:
    $key_7a44 = { 2e 2c [2] 5a 34 [2] 1d 36 [2] 5a 27 [2] 14 2b [2] 18 21 [2] 0f 2a [2] 14 64 [2] 29 }

  condition:
    any of them
}