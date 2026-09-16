rule TTP_XOR_MULT_DOSStub_1475 {
  strings:
    $key_1475 = { 40 1d [2] 34 05 [2] 73 07 [2] 34 16 [2] 7a 1a [2] 76 10 [2] 61 1b [2] 7a 55 [2] 47 }

  condition:
    any of them
}