rule TTP_XOR_MULT_DOSStub_b501 {
  strings:
    $key_b501 = { e1 69 [2] 95 71 [2] d2 73 [2] 95 62 [2] db 6e [2] d7 64 [2] c0 6f [2] db 21 [2] e6 }

  condition:
    any of them
}