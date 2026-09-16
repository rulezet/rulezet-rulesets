rule TTP_XOR_MULT_DOSStub_5949 {
  strings:
    $key_5949 = { 0d 21 [2] 79 39 [2] 3e 3b [2] 79 2a [2] 37 26 [2] 3b 2c [2] 2c 27 [2] 37 69 [2] 0a }

  condition:
    any of them
}