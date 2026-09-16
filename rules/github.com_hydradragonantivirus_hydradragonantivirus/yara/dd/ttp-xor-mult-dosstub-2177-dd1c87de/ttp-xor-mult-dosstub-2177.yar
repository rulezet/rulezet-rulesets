rule TTP_XOR_MULT_DOSStub_2177 {
  strings:
    $key_2177 = { 75 1f [2] 01 07 [2] 46 05 [2] 01 14 [2] 4f 18 [2] 43 12 [2] 54 19 [2] 4f 57 [2] 72 }

  condition:
    any of them
}