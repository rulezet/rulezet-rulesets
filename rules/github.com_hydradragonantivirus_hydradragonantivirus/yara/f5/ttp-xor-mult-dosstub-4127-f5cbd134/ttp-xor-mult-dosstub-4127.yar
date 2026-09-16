rule TTP_XOR_MULT_DOSStub_4127 {
  strings:
    $key_4127 = { 15 4f [2] 61 57 [2] 26 55 [2] 61 44 [2] 2f 48 [2] 23 42 [2] 34 49 [2] 2f 07 [2] 12 }

  condition:
    any of them
}