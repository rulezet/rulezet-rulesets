rule TTP_XOR_MULT_DOSStub_4aba {
  strings:
    $key_4aba = { 1e d2 [2] 6a ca [2] 2d c8 [2] 6a d9 [2] 24 d5 [2] 28 df [2] 3f d4 [2] 24 9a [2] 19 }

  condition:
    any of them
}