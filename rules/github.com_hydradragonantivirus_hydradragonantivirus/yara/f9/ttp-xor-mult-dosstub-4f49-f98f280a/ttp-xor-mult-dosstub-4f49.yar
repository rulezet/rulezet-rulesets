rule TTP_XOR_MULT_DOSStub_4f49 {
  strings:
    $key_4f49 = { 1b 21 [2] 6f 39 [2] 28 3b [2] 6f 2a [2] 21 26 [2] 2d 2c [2] 3a 27 [2] 21 69 [2] 1c }

  condition:
    any of them
}