rule TTP_XOR_MULT_DOSStub_bce6 {
  strings:
    $key_bce6 = { e8 8e [2] 9c 96 [2] db 94 [2] 9c 85 [2] d2 89 [2] de 83 [2] c9 88 [2] d2 c6 [2] ef }

  condition:
    any of them
}