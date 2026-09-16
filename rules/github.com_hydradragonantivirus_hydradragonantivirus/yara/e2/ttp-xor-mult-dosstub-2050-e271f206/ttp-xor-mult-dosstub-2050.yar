rule TTP_XOR_MULT_DOSStub_2050 {
  strings:
    $key_2050 = { 74 38 [2] 00 20 [2] 47 22 [2] 00 33 [2] 4e 3f [2] 42 35 [2] 55 3e [2] 4e 70 [2] 73 }

  condition:
    any of them
}