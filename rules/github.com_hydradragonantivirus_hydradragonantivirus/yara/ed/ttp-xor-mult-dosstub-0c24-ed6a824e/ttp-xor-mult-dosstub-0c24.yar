rule TTP_XOR_MULT_DOSStub_0c24 {
  strings:
    $key_0c24 = { 58 4c [2] 2c 54 [2] 6b 56 [2] 2c 47 [2] 62 4b [2] 6e 41 [2] 79 4a [2] 62 04 [2] 5f }

  condition:
    any of them
}