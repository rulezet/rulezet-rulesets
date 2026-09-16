rule TTP_XOR_MULT_DOSStub_591a {
  strings:
    $key_591a = { 0d 72 [2] 79 6a [2] 3e 68 [2] 79 79 [2] 37 75 [2] 3b 7f [2] 2c 74 [2] 37 3a [2] 0a }

  condition:
    any of them
}