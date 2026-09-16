rule TTP_XOR_MULT_DOSStub_b628 {
  strings:
    $key_b628 = { e2 40 [2] 96 58 [2] d1 5a [2] 96 4b [2] d8 47 [2] d4 4d [2] c3 46 [2] d8 08 [2] e5 }

  condition:
    any of them
}