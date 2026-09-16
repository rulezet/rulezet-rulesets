rule TTP_XOR_MULT_DOSStub_b57a {
  strings:
    $key_b57a = { e1 12 [2] 95 0a [2] d2 08 [2] 95 19 [2] db 15 [2] d7 1f [2] c0 14 [2] db 5a [2] e6 }

  condition:
    any of them
}