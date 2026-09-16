rule TTP_XOR_MULT_DOSStub_b660 {
  strings:
    $key_b660 = { e2 08 [2] 96 10 [2] d1 12 [2] 96 03 [2] d8 0f [2] d4 05 [2] c3 0e [2] d8 40 [2] e5 }

  condition:
    any of them
}