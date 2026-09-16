rule TTP_XOR_MULT_DOSStub_2147 {
  strings:
    $key_2147 = { 75 2f [2] 01 37 [2] 46 35 [2] 01 24 [2] 4f 28 [2] 43 22 [2] 54 29 [2] 4f 67 [2] 72 }

  condition:
    any of them
}