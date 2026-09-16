rule TTP_XOR_MULT_DOSStub_6227 {
  strings:
    $key_6227 = { 36 4f [2] 42 57 [2] 05 55 [2] 42 44 [2] 0c 48 [2] 00 42 [2] 17 49 [2] 0c 07 [2] 31 }

  condition:
    any of them
}