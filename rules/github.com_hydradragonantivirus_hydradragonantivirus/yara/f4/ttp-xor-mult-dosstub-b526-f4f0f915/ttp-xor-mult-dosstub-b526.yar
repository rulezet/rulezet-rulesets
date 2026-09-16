rule TTP_XOR_MULT_DOSStub_b526 {
  strings:
    $key_b526 = { e1 4e [2] 95 56 [2] d2 54 [2] 95 45 [2] db 49 [2] d7 43 [2] c0 48 [2] db 06 [2] e6 }

  condition:
    any of them
}