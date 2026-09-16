rule TTP_XOR_MULT_DOSStub_b636 {
  strings:
    $key_b636 = { e2 5e [2] 96 46 [2] d1 44 [2] 96 55 [2] d8 59 [2] d4 53 [2] c3 58 [2] d8 16 [2] e5 }

  condition:
    any of them
}