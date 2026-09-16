rule TTP_XOR_MULT_DOSStub_ebba {
  strings:
    $key_ebba = { bf d2 [2] cb ca [2] 8c c8 [2] cb d9 [2] 85 d5 [2] 89 df [2] 9e d4 [2] 85 9a [2] b8 }

  condition:
    any of them
}