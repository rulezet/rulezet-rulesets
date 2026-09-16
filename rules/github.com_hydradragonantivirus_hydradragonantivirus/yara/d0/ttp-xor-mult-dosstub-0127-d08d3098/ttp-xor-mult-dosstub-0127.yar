rule TTP_XOR_MULT_DOSStub_0127 {
  strings:
    $key_0127 = { 55 4f [2] 21 57 [2] 66 55 [2] 21 44 [2] 6f 48 [2] 63 42 [2] 74 49 [2] 6f 07 [2] 52 }

  condition:
    any of them
}