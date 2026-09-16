rule TTP_XOR_MULT_DOSStub_2666 {
  strings:
    $key_2666 = { 72 0e [2] 06 16 [2] 41 14 [2] 06 05 [2] 48 09 [2] 44 03 [2] 53 08 [2] 48 46 [2] 75 }

  condition:
    any of them
}