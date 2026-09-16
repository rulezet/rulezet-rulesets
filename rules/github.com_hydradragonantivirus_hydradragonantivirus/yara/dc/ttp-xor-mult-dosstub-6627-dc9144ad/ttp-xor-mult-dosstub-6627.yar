rule TTP_XOR_MULT_DOSStub_6627 {
  strings:
    $key_6627 = { 32 4f [2] 46 57 [2] 01 55 [2] 46 44 [2] 08 48 [2] 04 42 [2] 13 49 [2] 08 07 [2] 35 }

  condition:
    any of them
}