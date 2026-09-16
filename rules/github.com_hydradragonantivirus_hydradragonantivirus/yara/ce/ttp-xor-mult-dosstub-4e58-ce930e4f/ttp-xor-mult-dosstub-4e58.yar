rule TTP_XOR_MULT_DOSStub_4e58 {
  strings:
    $key_4e58 = { 1a 30 [2] 6e 28 [2] 29 2a [2] 6e 3b [2] 20 37 [2] 2c 3d [2] 3b 36 [2] 20 78 [2] 1d }

  condition:
    any of them
}