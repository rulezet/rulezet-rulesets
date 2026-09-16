rule TTP_XOR_MULT_DOSStub_bce5 {
  strings:
    $key_bce5 = { e8 8d [2] 9c 95 [2] db 97 [2] 9c 86 [2] d2 8a [2] de 80 [2] c9 8b [2] d2 c5 [2] ef }

  condition:
    any of them
}