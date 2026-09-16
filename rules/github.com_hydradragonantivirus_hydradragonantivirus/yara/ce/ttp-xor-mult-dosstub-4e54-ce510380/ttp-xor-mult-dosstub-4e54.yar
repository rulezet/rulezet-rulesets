rule TTP_XOR_MULT_DOSStub_4e54 {
  strings:
    $key_4e54 = { 1a 3c [2] 6e 24 [2] 29 26 [2] 6e 37 [2] 20 3b [2] 2c 31 [2] 3b 3a [2] 20 74 [2] 1d }

  condition:
    any of them
}