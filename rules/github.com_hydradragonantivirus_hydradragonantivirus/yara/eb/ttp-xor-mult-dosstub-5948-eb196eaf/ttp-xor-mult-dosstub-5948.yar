rule TTP_XOR_MULT_DOSStub_5948 {
  strings:
    $key_5948 = { 0d 20 [2] 79 38 [2] 3e 3a [2] 79 2b [2] 37 27 [2] 3b 2d [2] 2c 26 [2] 37 68 [2] 0a }

  condition:
    any of them
}