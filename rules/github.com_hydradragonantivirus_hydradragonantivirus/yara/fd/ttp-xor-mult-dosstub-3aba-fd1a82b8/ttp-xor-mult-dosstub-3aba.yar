rule TTP_XOR_MULT_DOSStub_3aba {
  strings:
    $key_3aba = { 6e d2 [2] 1a ca [2] 5d c8 [2] 1a d9 [2] 54 d5 [2] 58 df [2] 4f d4 [2] 54 9a [2] 69 }

  condition:
    any of them
}