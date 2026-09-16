rule TTP_XOR_MULT_DOSStub_7f5a {
  strings:
    $key_7f5a = { 2b 32 [2] 5f 2a [2] 18 28 [2] 5f 39 [2] 11 35 [2] 1d 3f [2] 0a 34 [2] 11 7a [2] 2c }

  condition:
    any of them
}