rule TTP_XOR_MULT_DOSStub_7fe9 {
  strings:
    $key_7fe9 = { 2b 81 [2] 5f 99 [2] 18 9b [2] 5f 8a [2] 11 86 [2] 1d 8c [2] 0a 87 [2] 11 c9 [2] 2c }

  condition:
    any of them
}