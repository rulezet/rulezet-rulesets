rule TTP_XOR_MULT_DOSStub_b5eb {
  strings:
    $key_b5eb = { e1 83 [2] 95 9b [2] d2 99 [2] 95 88 [2] db 84 [2] d7 8e [2] c0 85 [2] db cb [2] e6 }

  condition:
    any of them
}