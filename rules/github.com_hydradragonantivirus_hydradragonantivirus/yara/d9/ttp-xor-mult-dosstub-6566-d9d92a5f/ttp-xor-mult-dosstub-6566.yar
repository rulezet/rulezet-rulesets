rule TTP_XOR_MULT_DOSStub_6566 {
  strings:
    $key_6566 = { 31 0e [2] 45 16 [2] 02 14 [2] 45 05 [2] 0b 09 [2] 07 03 [2] 10 08 [2] 0b 46 [2] 36 }

  condition:
    any of them
}