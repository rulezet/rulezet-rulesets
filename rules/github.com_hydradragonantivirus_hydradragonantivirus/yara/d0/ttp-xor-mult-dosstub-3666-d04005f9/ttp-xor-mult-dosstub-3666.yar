rule TTP_XOR_MULT_DOSStub_3666 {
  strings:
    $key_3666 = { 62 0e [2] 16 16 [2] 51 14 [2] 16 05 [2] 58 09 [2] 54 03 [2] 43 08 [2] 58 46 [2] 65 }

  condition:
    any of them
}