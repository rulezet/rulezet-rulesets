rule TTP_XOR_MULT_DOSStub_3566 {
  strings:
    $key_3566 = { 61 0e [2] 15 16 [2] 52 14 [2] 15 05 [2] 5b 09 [2] 57 03 [2] 40 08 [2] 5b 46 [2] 66 }

  condition:
    any of them
}