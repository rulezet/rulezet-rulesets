rule TTP_XOR_MULT_DOSStub_5247 {
  strings:
    $key_5247 = { 06 2f [2] 72 37 [2] 35 35 [2] 72 24 [2] 3c 28 [2] 30 22 [2] 27 29 [2] 3c 67 [2] 01 }

  condition:
    any of them
}