rule TTP_XOR_MULT_DOSStub_2075 {
  strings:
    $key_2075 = { 74 1d [2] 00 05 [2] 47 07 [2] 00 16 [2] 4e 1a [2] 42 10 [2] 55 1b [2] 4e 55 [2] 73 }

  condition:
    any of them
}