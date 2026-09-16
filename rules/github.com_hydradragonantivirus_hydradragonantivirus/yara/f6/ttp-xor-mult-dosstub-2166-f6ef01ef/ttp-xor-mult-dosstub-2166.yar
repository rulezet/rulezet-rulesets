rule TTP_XOR_MULT_DOSStub_2166 {
  strings:
    $key_2166 = { 75 0e [2] 01 16 [2] 46 14 [2] 01 05 [2] 4f 09 [2] 43 03 [2] 54 08 [2] 4f 46 [2] 72 }

  condition:
    any of them
}