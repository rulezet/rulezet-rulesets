rule TTP_XOR_MULT_DOSStub_4e25 {
  strings:
    $key_4e25 = { 1a 4d [2] 6e 55 [2] 29 57 [2] 6e 46 [2] 20 4a [2] 2c 40 [2] 3b 4b [2] 20 05 [2] 1d }

  condition:
    any of them
}