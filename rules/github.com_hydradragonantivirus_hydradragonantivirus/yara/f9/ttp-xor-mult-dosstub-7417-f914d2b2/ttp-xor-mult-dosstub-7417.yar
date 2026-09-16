rule TTP_XOR_MULT_DOSStub_7417 {
  strings:
    $key_7417 = { 20 7f [2] 54 67 [2] 13 65 [2] 54 74 [2] 1a 78 [2] 16 72 [2] 01 79 [2] 1a 37 [2] 27 }

  condition:
    any of them
}