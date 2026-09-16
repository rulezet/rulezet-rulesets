rule TTP_XOR_MULT_DOSStub_1c49 {
  strings:
    $key_1c49 = { 48 21 [2] 3c 39 [2] 7b 3b [2] 3c 2a [2] 72 26 [2] 7e 2c [2] 69 27 [2] 72 69 [2] 4f }

  condition:
    any of them
}