rule TTP_XOR_MULT_DOSStub_b506 {
  strings:
    $key_b506 = { e1 6e [2] 95 76 [2] d2 74 [2] 95 65 [2] db 69 [2] d7 63 [2] c0 68 [2] db 26 [2] e6 }

  condition:
    any of them
}