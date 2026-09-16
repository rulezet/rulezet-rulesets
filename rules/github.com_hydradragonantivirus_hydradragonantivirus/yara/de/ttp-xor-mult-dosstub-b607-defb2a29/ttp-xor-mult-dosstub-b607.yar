rule TTP_XOR_MULT_DOSStub_b607 {
  strings:
    $key_b607 = { e2 6f [2] 96 77 [2] d1 75 [2] 96 64 [2] d8 68 [2] d4 62 [2] c3 69 [2] d8 27 [2] e5 }

  condition:
    any of them
}