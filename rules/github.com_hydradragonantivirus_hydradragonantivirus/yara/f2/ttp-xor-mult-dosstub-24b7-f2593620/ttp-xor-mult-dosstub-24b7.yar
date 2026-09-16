rule TTP_XOR_MULT_DOSStub_24b7 {
  strings:
    $key_24b7 = { 70 df [2] 04 c7 [2] 43 c5 [2] 04 d4 [2] 4a d8 [2] 46 d2 [2] 51 d9 [2] 4a 97 [2] 77 }

  condition:
    any of them
}