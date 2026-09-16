rule TTP_XOR_MULT_DOSStub_b661 {
  strings:
    $key_b661 = { e2 09 [2] 96 11 [2] d1 13 [2] 96 02 [2] d8 0e [2] d4 04 [2] c3 0f [2] d8 41 [2] e5 }

  condition:
    any of them
}