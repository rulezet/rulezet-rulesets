rule TTP_XOR_MULT_DOSStub_b7b7 {
  strings:
    $key_b7b7 = { e3 df [2] 97 c7 [2] d0 c5 [2] 97 d4 [2] d9 d8 [2] d5 d2 [2] c2 d9 [2] d9 97 [2] e4 }

  condition:
    any of them
}