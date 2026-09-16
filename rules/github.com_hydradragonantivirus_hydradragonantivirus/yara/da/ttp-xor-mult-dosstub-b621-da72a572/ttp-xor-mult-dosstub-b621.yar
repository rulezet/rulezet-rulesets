rule TTP_XOR_MULT_DOSStub_b621 {
  strings:
    $key_b621 = { e2 49 [2] 96 51 [2] d1 53 [2] 96 42 [2] d8 4e [2] d4 44 [2] c3 4f [2] d8 01 [2] e5 }

  condition:
    any of them
}