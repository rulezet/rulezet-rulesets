rule TTP_XOR_MULT_DOSStub_07fb {
  strings:
    $key_07fb = { 53 93 [2] 27 8b [2] 60 89 [2] 27 98 [2] 69 94 [2] 65 9e [2] 72 95 [2] 69 db [2] 54 }

  condition:
    any of them
}