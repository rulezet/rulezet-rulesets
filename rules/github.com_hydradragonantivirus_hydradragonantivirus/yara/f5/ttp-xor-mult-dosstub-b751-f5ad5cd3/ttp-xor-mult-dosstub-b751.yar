rule TTP_XOR_MULT_DOSStub_b751 {
  strings:
    $key_b751 = { e3 39 [2] 97 21 [2] d0 23 [2] 97 32 [2] d9 3e [2] d5 34 [2] c2 3f [2] d9 71 [2] e4 }

  condition:
    any of them
}