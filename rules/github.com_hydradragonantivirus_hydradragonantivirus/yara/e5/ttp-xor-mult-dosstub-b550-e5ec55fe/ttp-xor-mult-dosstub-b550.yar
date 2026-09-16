rule TTP_XOR_MULT_DOSStub_b550 {
  strings:
    $key_b550 = { e1 38 [2] 95 20 [2] d2 22 [2] 95 33 [2] db 3f [2] d7 35 [2] c0 3e [2] db 70 [2] e6 }

  condition:
    any of them
}