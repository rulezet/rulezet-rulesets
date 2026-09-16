rule TTP_XOR_MULT_DOSStub_4e34 {
  strings:
    $key_4e34 = { 1a 5c [2] 6e 44 [2] 29 46 [2] 6e 57 [2] 20 5b [2] 2c 51 [2] 3b 5a [2] 20 14 [2] 1d }

  condition:
    any of them
}