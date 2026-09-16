rule TTP_XOR_MULT_DOSStub_4e65 {
  strings:
    $key_4e65 = { 1a 0d [2] 6e 15 [2] 29 17 [2] 6e 06 [2] 20 0a [2] 2c 00 [2] 3b 0b [2] 20 45 [2] 1d }

  condition:
    any of them
}