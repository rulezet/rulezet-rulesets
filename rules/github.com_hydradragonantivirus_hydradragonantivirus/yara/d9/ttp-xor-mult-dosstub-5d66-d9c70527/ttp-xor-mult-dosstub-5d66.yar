rule TTP_XOR_MULT_DOSStub_5d66 {
  strings:
    $key_5d66 = { 09 0e [2] 7d 16 [2] 3a 14 [2] 7d 05 [2] 33 09 [2] 3f 03 [2] 28 08 [2] 33 46 [2] 0e }

  condition:
    any of them
}