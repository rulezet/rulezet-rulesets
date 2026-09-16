rule TTP_XOR_MULT_DOSStub_7864 {
  strings:
    $key_7864 = { 2c 0c [2] 58 14 [2] 1f 16 [2] 58 07 [2] 16 0b [2] 1a 01 [2] 0d 0a [2] 16 44 [2] 2b }

  condition:
    any of them
}