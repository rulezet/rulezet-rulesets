rule TTP_XOR_MULT_DOSStub_5968 {
  strings:
    $key_5968 = { 0d 00 [2] 79 18 [2] 3e 1a [2] 79 0b [2] 37 07 [2] 3b 0d [2] 2c 06 [2] 37 48 [2] 0a }

  condition:
    any of them
}