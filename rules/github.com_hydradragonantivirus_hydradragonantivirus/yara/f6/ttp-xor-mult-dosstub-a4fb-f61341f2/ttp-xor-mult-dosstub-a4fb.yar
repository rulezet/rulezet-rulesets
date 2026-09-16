rule TTP_XOR_MULT_DOSStub_a4fb {
  strings:
    $key_a4fb = { f0 93 [2] 84 8b [2] c3 89 [2] 84 98 [2] ca 94 [2] c6 9e [2] d1 95 [2] ca db [2] f7 }

  condition:
    any of them
}