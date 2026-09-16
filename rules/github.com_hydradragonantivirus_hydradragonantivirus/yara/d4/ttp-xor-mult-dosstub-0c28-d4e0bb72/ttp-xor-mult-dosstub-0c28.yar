rule TTP_XOR_MULT_DOSStub_0c28 {
  strings:
    $key_0c28 = { 58 40 [2] 2c 58 [2] 6b 5a [2] 2c 4b [2] 62 47 [2] 6e 4d [2] 79 46 [2] 62 08 [2] 5f }

  condition:
    any of them
}