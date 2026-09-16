rule TTP_XOR_MULT_DOSStub_6c46 {
  strings:
    $key_6c46 = { 38 2e [2] 4c 36 [2] 0b 34 [2] 4c 25 [2] 02 29 [2] 0e 23 [2] 19 28 [2] 02 66 [2] 3f }

  condition:
    any of them
}