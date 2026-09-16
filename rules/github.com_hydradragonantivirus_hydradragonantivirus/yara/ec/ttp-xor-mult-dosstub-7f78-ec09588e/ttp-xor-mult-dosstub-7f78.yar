rule TTP_XOR_MULT_DOSStub_7f78 {
  strings:
    $key_7f78 = { 2b 10 [2] 5f 08 [2] 18 0a [2] 5f 1b [2] 11 17 [2] 1d 1d [2] 0a 16 [2] 11 58 [2] 2c }

  condition:
    any of them
}