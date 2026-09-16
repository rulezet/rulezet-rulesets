rule TTP_XOR_MULT_DOSStub_b2fb {
  strings:
    $key_b2fb = { e6 93 [2] 92 8b [2] d5 89 [2] 92 98 [2] dc 94 [2] d0 9e [2] c7 95 [2] dc db [2] e1 }

  condition:
    any of them
}