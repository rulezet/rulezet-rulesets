rule TTP_XOR_MULT_DOSStub_1561 {
  strings:
    $key_1561 = { 41 09 [2] 35 11 [2] 72 13 [2] 35 02 [2] 7b 0e [2] 77 04 [2] 60 0f [2] 7b 41 [2] 46 }

  condition:
    any of them
}