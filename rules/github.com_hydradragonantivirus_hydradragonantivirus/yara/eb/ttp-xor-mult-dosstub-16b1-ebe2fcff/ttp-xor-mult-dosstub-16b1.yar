rule TTP_XOR_MULT_DOSStub_16b1 {
  strings:
    $key_16b1 = { 42 d9 [2] 36 c1 [2] 71 c3 [2] 36 d2 [2] 78 de [2] 74 d4 [2] 63 df [2] 78 91 [2] 45 }

  condition:
    any of them
}