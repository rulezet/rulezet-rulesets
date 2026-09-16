rule TTP_XOR_MULT_DOSStub_5527 {
  strings:
    $key_5527 = { 01 4f [2] 75 57 [2] 32 55 [2] 75 44 [2] 3b 48 [2] 37 42 [2] 20 49 [2] 3b 07 [2] 06 }

  condition:
    any of them
}