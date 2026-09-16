rule TTP_XOR_MULT_DOSStub_4278 {
  strings:
    $key_4278 = { 16 10 [2] 62 08 [2] 25 0a [2] 62 1b [2] 2c 17 [2] 20 1d [2] 37 16 [2] 2c 58 [2] 11 }

  condition:
    any of them
}