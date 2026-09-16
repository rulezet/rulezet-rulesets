rule TTP_XOR_MULT_DOSStub_b614 {
  strings:
    $key_b614 = { e2 7c [2] 96 64 [2] d1 66 [2] 96 77 [2] d8 7b [2] d4 71 [2] c3 7a [2] d8 34 [2] e5 }

  condition:
    any of them
}