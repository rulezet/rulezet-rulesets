rule TTP_XOR_MULT_DOSStub_7f74 {
  strings:
    $key_7f74 = { 2b 1c [2] 5f 04 [2] 18 06 [2] 5f 17 [2] 11 1b [2] 1d 11 [2] 0a 1a [2] 11 54 [2] 2c }

  condition:
    any of them
}