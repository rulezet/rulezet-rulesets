rule TTP_XOR_MULT_DOSStub_b520 {
  strings:
    $key_b520 = { e1 48 [2] 95 50 [2] d2 52 [2] 95 43 [2] db 4f [2] d7 45 [2] c0 4e [2] db 00 [2] e6 }

  condition:
    any of them
}