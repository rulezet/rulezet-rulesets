rule TTP_XOR_MULT_DOSStub_b507 {
  strings:
    $key_b507 = { e1 6f [2] 95 77 [2] d2 75 [2] 95 64 [2] db 68 [2] d7 62 [2] c0 69 [2] db 27 [2] e6 }

  condition:
    any of them
}