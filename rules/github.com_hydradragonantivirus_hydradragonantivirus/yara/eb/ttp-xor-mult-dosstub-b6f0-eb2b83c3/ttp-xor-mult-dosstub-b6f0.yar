rule TTP_XOR_MULT_DOSStub_b6f0 {
  strings:
    $key_b6f0 = { e2 98 [2] 96 80 [2] d1 82 [2] 96 93 [2] d8 9f [2] d4 95 [2] c3 9e [2] d8 d0 [2] e5 }

  condition:
    any of them
}