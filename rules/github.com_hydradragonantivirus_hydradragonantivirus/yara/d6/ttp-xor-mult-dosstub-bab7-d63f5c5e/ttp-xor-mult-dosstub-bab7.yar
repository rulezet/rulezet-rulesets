rule TTP_XOR_MULT_DOSStub_bab7 {
  strings:
    $key_bab7 = { ee df [2] 9a c7 [2] dd c5 [2] 9a d4 [2] d4 d8 [2] d8 d2 [2] cf d9 [2] d4 97 [2] e9 }

  condition:
    any of them
}