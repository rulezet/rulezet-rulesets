rule TTP_XOR_MULT_DOSStub_a2fb {
  strings:
    $key_a2fb = { f6 93 [2] 82 8b [2] c5 89 [2] 82 98 [2] cc 94 [2] c0 9e [2] d7 95 [2] cc db [2] f1 }

  condition:
    any of them
}