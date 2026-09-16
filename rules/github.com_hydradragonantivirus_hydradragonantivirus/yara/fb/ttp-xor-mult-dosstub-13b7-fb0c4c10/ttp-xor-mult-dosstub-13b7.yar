rule TTP_XOR_MULT_DOSStub_13b7 {
  strings:
    $key_13b7 = { 47 df [2] 33 c7 [2] 74 c5 [2] 33 d4 [2] 7d d8 [2] 71 d2 [2] 66 d9 [2] 7d 97 [2] 40 }

  condition:
    any of them
}