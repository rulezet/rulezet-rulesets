rule TTP_XOR_MULT_DOSStub_5945 {
  strings:
    $key_5945 = { 0d 2d [2] 79 35 [2] 3e 37 [2] 79 26 [2] 37 2a [2] 3b 20 [2] 2c 2b [2] 37 65 [2] 0a }

  condition:
    any of them
}