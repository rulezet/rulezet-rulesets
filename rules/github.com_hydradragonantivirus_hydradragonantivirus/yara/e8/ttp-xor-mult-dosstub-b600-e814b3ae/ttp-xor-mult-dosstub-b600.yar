rule TTP_XOR_MULT_DOSStub_b600 {
  strings:
    $key_b600 = { e2 68 [2] 96 70 [2] d1 72 [2] 96 63 [2] d8 6f [2] d4 65 [2] c3 6e [2] d8 20 [2] e5 }

  condition:
    any of them
}