rule TTP_XOR_MULT_DOSStub_15b7 {
  strings:
    $key_15b7 = { 41 df [2] 35 c7 [2] 72 c5 [2] 35 d4 [2] 7b d8 [2] 77 d2 [2] 60 d9 [2] 7b 97 [2] 46 }

  condition:
    any of them
}