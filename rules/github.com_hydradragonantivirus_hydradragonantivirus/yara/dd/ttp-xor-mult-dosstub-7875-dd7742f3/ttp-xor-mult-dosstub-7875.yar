rule TTP_XOR_MULT_DOSStub_7875 {
  strings:
    $key_7875 = { 2c 1d [2] 58 05 [2] 1f 07 [2] 58 16 [2] 16 1a [2] 1a 10 [2] 0d 1b [2] 16 55 [2] 2b }

  condition:
    any of them
}