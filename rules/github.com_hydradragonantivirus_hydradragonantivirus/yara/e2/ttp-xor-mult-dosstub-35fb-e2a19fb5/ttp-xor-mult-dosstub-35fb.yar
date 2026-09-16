rule TTP_XOR_MULT_DOSStub_35fb {
  strings:
    $key_35fb = { 61 93 [2] 15 8b [2] 52 89 [2] 15 98 [2] 5b 94 [2] 57 9e [2] 40 95 [2] 5b db [2] 66 }

  condition:
    any of them
}