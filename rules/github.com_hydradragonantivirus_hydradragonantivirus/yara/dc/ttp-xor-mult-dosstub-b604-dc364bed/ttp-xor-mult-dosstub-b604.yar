rule TTP_XOR_MULT_DOSStub_b604 {
  strings:
    $key_b604 = { e2 6c [2] 96 74 [2] d1 76 [2] 96 67 [2] d8 6b [2] d4 61 [2] c3 6a [2] d8 24 [2] e5 }

  condition:
    any of them
}