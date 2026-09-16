rule TTP_XOR_MULT_DOSStub_b647 {
  strings:
    $key_b647 = { e2 2f [2] 96 37 [2] d1 35 [2] 96 24 [2] d8 28 [2] d4 22 [2] c3 29 [2] d8 67 [2] e5 }

  condition:
    any of them
}