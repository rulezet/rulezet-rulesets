rule TTP_XOR_MULT_DOSStub_b5f0 {
  strings:
    $key_b5f0 = { e1 98 [2] 95 80 [2] d2 82 [2] 95 93 [2] db 9f [2] d7 95 [2] c0 9e [2] db d0 [2] e6 }

  condition:
    any of them
}