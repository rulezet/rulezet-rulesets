rule TTP_XOR_MULT_DOSStub_0147 {
  strings:
    $key_0147 = { 55 2f [2] 21 37 [2] 66 35 [2] 21 24 [2] 6f 28 [2] 63 22 [2] 74 29 [2] 6f 67 [2] 52 }

  condition:
    any of them
}