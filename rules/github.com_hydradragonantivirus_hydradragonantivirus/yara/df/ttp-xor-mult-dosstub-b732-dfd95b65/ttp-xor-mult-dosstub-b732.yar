rule TTP_XOR_MULT_DOSStub_b732 {
  strings:
    $key_b732 = { e3 5a [2] 97 42 [2] d0 40 [2] 97 51 [2] d9 5d [2] d5 57 [2] c2 5c [2] d9 12 [2] e4 }

  condition:
    any of them
}