rule TTP_XOR_MULT_DOSStub_2076 {
  strings:
    $key_2076 = { 74 1e [2] 00 06 [2] 47 04 [2] 00 15 [2] 4e 19 [2] 42 13 [2] 55 18 [2] 4e 56 [2] 73 }

  condition:
    any of them
}