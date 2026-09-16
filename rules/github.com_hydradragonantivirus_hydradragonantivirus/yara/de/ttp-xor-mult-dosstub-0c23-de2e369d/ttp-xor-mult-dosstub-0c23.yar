rule TTP_XOR_MULT_DOSStub_0c23 {
  strings:
    $key_0c23 = { 58 4b [2] 2c 53 [2] 6b 51 [2] 2c 40 [2] 62 4c [2] 6e 46 [2] 79 4d [2] 62 03 [2] 5f }

  condition:
    any of them
}