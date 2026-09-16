rule TTP_XOR_MULT_DOSStub_4e42 {
  strings:
    $key_4e42 = { 1a 2a [2] 6e 32 [2] 29 30 [2] 6e 21 [2] 20 2d [2] 2c 27 [2] 3b 2c [2] 20 62 [2] 1d }

  condition:
    any of them
}