rule TTP_XOR_MULT_DOSStub_4e69 {
  strings:
    $key_4e69 = { 1a 01 [2] 6e 19 [2] 29 1b [2] 6e 0a [2] 20 06 [2] 2c 0c [2] 3b 07 [2] 20 49 [2] 1d }

  condition:
    any of them
}