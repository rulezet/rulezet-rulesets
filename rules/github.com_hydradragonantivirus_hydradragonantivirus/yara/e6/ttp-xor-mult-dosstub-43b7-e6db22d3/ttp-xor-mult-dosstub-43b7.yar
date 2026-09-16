rule TTP_XOR_MULT_DOSStub_43b7 {
  strings:
    $key_43b7 = { 17 df [2] 63 c7 [2] 24 c5 [2] 63 d4 [2] 2d d8 [2] 21 d2 [2] 36 d9 [2] 2d 97 [2] 10 }

  condition:
    any of them
}