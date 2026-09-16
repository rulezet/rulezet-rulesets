rule TTP_XOR_MULT_DOSStub_2066 {
  strings:
    $key_2066 = { 74 0e [2] 00 16 [2] 47 14 [2] 00 05 [2] 4e 09 [2] 42 03 [2] 55 08 [2] 4e 46 [2] 73 }

  condition:
    any of them
}