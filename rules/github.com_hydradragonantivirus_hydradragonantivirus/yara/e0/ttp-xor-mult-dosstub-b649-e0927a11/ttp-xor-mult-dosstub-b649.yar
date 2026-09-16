rule TTP_XOR_MULT_DOSStub_b649 {
  strings:
    $key_b649 = { e2 21 [2] 96 39 [2] d1 3b [2] 96 2a [2] d8 26 [2] d4 2c [2] c3 27 [2] d8 69 [2] e5 }

  condition:
    any of them
}