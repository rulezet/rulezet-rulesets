rule TTP_XOR_MULT_DOSStub_4e35 {
  strings:
    $key_4e35 = { 1a 5d [2] 6e 45 [2] 29 47 [2] 6e 56 [2] 20 5a [2] 2c 50 [2] 3b 5b [2] 20 15 [2] 1d }

  condition:
    any of them
}