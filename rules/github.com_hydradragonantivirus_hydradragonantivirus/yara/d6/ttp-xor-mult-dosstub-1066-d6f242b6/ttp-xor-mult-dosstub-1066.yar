rule TTP_XOR_MULT_DOSStub_1066 {
  strings:
    $key_1066 = { 44 0e [2] 30 16 [2] 77 14 [2] 30 05 [2] 7e 09 [2] 72 03 [2] 65 08 [2] 7e 46 [2] 43 }

  condition:
    any of them
}