rule TTP_XOR_MULT_DOSStub_21f7 {
  strings:
    $key_21f7 = { 75 9f [2] 01 87 [2] 46 85 [2] 01 94 [2] 4f 98 [2] 43 92 [2] 54 99 [2] 4f d7 [2] 72 }

  condition:
    any of them
}