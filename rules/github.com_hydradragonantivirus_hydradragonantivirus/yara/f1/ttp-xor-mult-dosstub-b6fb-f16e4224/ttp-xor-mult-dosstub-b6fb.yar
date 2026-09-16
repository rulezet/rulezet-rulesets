rule TTP_XOR_MULT_DOSStub_b6fb {
  strings:
    $key_b6fb = { e2 93 [2] 96 8b [2] d1 89 [2] 96 98 [2] d8 94 [2] d4 9e [2] c3 95 [2] d8 db [2] e5 }

  condition:
    any of them
}