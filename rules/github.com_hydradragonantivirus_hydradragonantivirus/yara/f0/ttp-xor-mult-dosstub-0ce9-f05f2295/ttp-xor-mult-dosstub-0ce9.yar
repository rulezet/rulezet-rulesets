rule TTP_XOR_MULT_DOSStub_0ce9 {
  strings:
    $key_0ce9 = { 58 81 [2] 2c 99 [2] 6b 9b [2] 2c 8a [2] 62 86 [2] 6e 8c [2] 79 87 [2] 62 c9 [2] 5f }

  condition:
    any of them
}