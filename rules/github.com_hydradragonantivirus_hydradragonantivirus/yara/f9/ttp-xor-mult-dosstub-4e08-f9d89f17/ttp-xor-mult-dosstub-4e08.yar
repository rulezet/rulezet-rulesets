rule TTP_XOR_MULT_DOSStub_4e08 {
  strings:
    $key_4e08 = { 1a 60 [2] 6e 78 [2] 29 7a [2] 6e 6b [2] 20 67 [2] 2c 6d [2] 3b 66 [2] 20 28 [2] 1d }

  condition:
    any of them
}