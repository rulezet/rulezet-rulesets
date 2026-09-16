rule TTP_XOR_MULT_DOSStub_7249 {
  strings:
    $key_7249 = { 26 21 [2] 52 39 [2] 15 3b [2] 52 2a [2] 1c 26 [2] 10 2c [2] 07 27 [2] 1c 69 [2] 21 }

  condition:
    any of them
}