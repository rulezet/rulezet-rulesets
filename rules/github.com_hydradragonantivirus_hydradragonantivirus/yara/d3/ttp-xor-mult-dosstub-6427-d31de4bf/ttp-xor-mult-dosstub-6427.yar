rule TTP_XOR_MULT_DOSStub_6427 {
  strings:
    $key_6427 = { 30 4f [2] 44 57 [2] 03 55 [2] 44 44 [2] 0a 48 [2] 06 42 [2] 11 49 [2] 0a 07 [2] 37 }

  condition:
    any of them
}