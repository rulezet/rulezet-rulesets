rule TTP_XOR_MULT_DOSStub_33b7 {
  strings:
    $key_33b7 = { 67 df [2] 13 c7 [2] 54 c5 [2] 13 d4 [2] 5d d8 [2] 51 d2 [2] 46 d9 [2] 5d 97 [2] 60 }

  condition:
    any of them
}