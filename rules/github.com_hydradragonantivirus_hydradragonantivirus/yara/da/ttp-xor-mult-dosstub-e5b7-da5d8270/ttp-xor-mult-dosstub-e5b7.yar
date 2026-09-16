rule TTP_XOR_MULT_DOSStub_e5b7 {
  strings:
    $key_e5b7 = { b1 df [2] c5 c7 [2] 82 c5 [2] c5 d4 [2] 8b d8 [2] 87 d2 [2] 90 d9 [2] 8b 97 [2] b6 }

  condition:
    any of them
}