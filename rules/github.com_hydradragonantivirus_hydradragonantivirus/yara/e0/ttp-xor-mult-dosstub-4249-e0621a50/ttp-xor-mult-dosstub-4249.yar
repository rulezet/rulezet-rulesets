rule TTP_XOR_MULT_DOSStub_4249 {
  strings:
    $key_4249 = { 16 21 [2] 62 39 [2] 25 3b [2] 62 2a [2] 2c 26 [2] 20 2c [2] 37 27 [2] 2c 69 [2] 11 }

  condition:
    any of them
}