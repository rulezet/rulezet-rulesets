rule TTP_XOR_MULT_DOSStub_7854 {
  strings:
    $key_7854 = { 2c 3c [2] 58 24 [2] 1f 26 [2] 58 37 [2] 16 3b [2] 1a 31 [2] 0d 3a [2] 16 74 [2] 2b }

  condition:
    any of them
}