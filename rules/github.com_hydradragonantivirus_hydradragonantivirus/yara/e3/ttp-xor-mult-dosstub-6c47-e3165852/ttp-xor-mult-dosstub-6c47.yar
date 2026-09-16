rule TTP_XOR_MULT_DOSStub_6c47 {
  strings:
    $key_6c47 = { 38 2f [2] 4c 37 [2] 0b 35 [2] 4c 24 [2] 02 28 [2] 0e 22 [2] 19 29 [2] 02 67 [2] 3f }

  condition:
    any of them
}