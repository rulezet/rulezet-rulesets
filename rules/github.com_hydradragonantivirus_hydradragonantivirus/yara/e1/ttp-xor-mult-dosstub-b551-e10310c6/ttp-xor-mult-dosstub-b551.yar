rule TTP_XOR_MULT_DOSStub_b551 {
  strings:
    $key_b551 = { e1 39 [2] 95 21 [2] d2 23 [2] 95 32 [2] db 3e [2] d7 34 [2] c0 3f [2] db 71 [2] e6 }

  condition:
    any of them
}