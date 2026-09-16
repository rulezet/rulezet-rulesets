rule TTP_XOR_MULT_DOSStub_7f09 {
  strings:
    $key_7f09 = { 2b 61 [2] 5f 79 [2] 18 7b [2] 5f 6a [2] 11 66 [2] 1d 6c [2] 0a 67 [2] 11 29 [2] 2c }

  condition:
    any of them
}