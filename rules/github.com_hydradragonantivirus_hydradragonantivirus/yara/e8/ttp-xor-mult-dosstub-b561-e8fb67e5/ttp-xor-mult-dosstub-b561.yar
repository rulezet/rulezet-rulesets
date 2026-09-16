rule TTP_XOR_MULT_DOSStub_b561 {
  strings:
    $key_b561 = { e1 09 [2] 95 11 [2] d2 13 [2] 95 02 [2] db 0e [2] d7 04 [2] c0 0f [2] db 41 [2] e6 }

  condition:
    any of them
}