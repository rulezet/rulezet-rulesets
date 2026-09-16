rule TTP_XOR_MULT_DOSStub_e1b7 {
  strings:
    $key_e1b7 = { b5 df [2] c1 c7 [2] 86 c5 [2] c1 d4 [2] 8f d8 [2] 83 d2 [2] 94 d9 [2] 8f 97 [2] b2 }

  condition:
    any of them
}