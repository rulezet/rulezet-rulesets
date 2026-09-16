rule TTP_XOR_MULT_DOSStub_6166 {
  strings:
    $key_6166 = { 35 0e [2] 41 16 [2] 06 14 [2] 41 05 [2] 0f 09 [2] 03 03 [2] 14 08 [2] 0f 46 [2] 32 }

  condition:
    any of them
}