rule TTP_XOR_MULT_DOSStub_b736 {
  strings:
    $key_b736 = { e3 5e [2] 97 46 [2] d0 44 [2] 97 55 [2] d9 59 [2] d5 53 [2] c2 58 [2] d9 16 [2] e4 }

  condition:
    any of them
}