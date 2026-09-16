rule TTP_XOR_MULT_DOSStub_2068 {
  strings:
    $key_2068 = { 74 00 [2] 00 18 [2] 47 1a [2] 00 0b [2] 4e 07 [2] 42 0d [2] 55 06 [2] 4e 48 [2] 73 }

  condition:
    any of them
}