rule TTP_XOR_MULT_DOSStub_b549 {
  strings:
    $key_b549 = { e1 21 [2] 95 39 [2] d2 3b [2] 95 2a [2] db 26 [2] d7 2c [2] c0 27 [2] db 69 [2] e6 }

  condition:
    any of them
}