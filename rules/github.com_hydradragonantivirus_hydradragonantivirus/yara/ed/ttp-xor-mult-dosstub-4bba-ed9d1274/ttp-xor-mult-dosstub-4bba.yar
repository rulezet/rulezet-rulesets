rule TTP_XOR_MULT_DOSStub_4bba {
  strings:
    $key_4bba = { 1f d2 [2] 6b ca [2] 2c c8 [2] 6b d9 [2] 25 d5 [2] 29 df [2] 3e d4 [2] 25 9a [2] 18 }

  condition:
    any of them
}