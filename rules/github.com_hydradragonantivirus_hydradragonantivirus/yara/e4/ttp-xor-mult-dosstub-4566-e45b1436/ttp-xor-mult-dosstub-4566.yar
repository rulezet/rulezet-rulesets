rule TTP_XOR_MULT_DOSStub_4566 {
  strings:
    $key_4566 = { 11 0e [2] 65 16 [2] 22 14 [2] 65 05 [2] 2b 09 [2] 27 03 [2] 30 08 [2] 2b 46 [2] 16 }

  condition:
    any of them
}