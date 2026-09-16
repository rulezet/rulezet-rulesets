rule TTP_XOR_MULT_DOSStub_b6e7 {
  strings:
    $key_b6e7 = { e2 8f [2] 96 97 [2] d1 95 [2] 96 84 [2] d8 88 [2] d4 82 [2] c3 89 [2] d8 c7 [2] e5 }

  condition:
    any of them
}