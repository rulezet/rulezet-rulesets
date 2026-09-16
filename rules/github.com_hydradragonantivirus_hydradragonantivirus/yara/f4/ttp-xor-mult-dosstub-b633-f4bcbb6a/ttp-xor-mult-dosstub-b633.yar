rule TTP_XOR_MULT_DOSStub_b633 {
  strings:
    $key_b633 = { e2 5b [2] 96 43 [2] d1 41 [2] 96 50 [2] d8 5c [2] d4 56 [2] c3 5d [2] d8 13 [2] e5 }

  condition:
    any of them
}