rule TTP_XOR_MULT_DOSStub_4e09 {
  strings:
    $key_4e09 = { 1a 61 [2] 6e 79 [2] 29 7b [2] 6e 6a [2] 20 66 [2] 2c 6c [2] 3b 67 [2] 20 29 [2] 1d }

  condition:
    any of them
}