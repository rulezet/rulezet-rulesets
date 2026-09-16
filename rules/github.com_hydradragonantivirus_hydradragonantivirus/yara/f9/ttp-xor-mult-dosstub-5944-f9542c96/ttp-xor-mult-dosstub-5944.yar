rule TTP_XOR_MULT_DOSStub_5944 {
  strings:
    $key_5944 = { 0d 2c [2] 79 34 [2] 3e 36 [2] 79 27 [2] 37 2b [2] 3b 21 [2] 2c 2a [2] 37 64 [2] 0a }

  condition:
    any of them
}