rule TTP_XOR_MULT_DOSStub_2057 {
  strings:
    $key_2057 = { 74 3f [2] 00 27 [2] 47 25 [2] 00 34 [2] 4e 38 [2] 42 32 [2] 55 39 [2] 4e 77 [2] 73 }

  condition:
    any of them
}