rule TTP_XOR_MULT_DOSStub_7f62 {
  strings:
    $key_7f62 = { 2b 0a [2] 5f 12 [2] 18 10 [2] 5f 01 [2] 11 0d [2] 1d 07 [2] 0a 0c [2] 11 42 [2] 2c }

  condition:
    any of them
}