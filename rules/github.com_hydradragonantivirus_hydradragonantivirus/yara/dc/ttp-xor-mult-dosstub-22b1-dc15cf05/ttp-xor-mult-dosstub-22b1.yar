rule TTP_XOR_MULT_DOSStub_22b1 {
  strings:
    $key_22b1 = { 76 d9 [2] 02 c1 [2] 45 c3 [2] 02 d2 [2] 4c de [2] 40 d4 [2] 57 df [2] 4c 91 [2] 71 }

  condition:
    any of them
}