rule TTP_XOR_MULT_DOSStub_b654 {
  strings:
    $key_b654 = { e2 3c [2] 96 24 [2] d1 26 [2] 96 37 [2] d8 3b [2] d4 31 [2] c3 3a [2] d8 74 [2] e5 }

  condition:
    any of them
}