rule TTP_XOR_MULT_DOSStub_7809 {
  strings:
    $key_7809 = { 2c 61 [2] 58 79 [2] 1f 7b [2] 58 6a [2] 16 66 [2] 1a 6c [2] 0d 67 [2] 16 29 [2] 2b }

  condition:
    any of them
}