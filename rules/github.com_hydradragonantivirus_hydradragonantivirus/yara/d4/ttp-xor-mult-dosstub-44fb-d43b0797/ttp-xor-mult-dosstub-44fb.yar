rule TTP_XOR_MULT_DOSStub_44fb {
  strings:
    $key_44fb = { 10 93 [2] 64 8b [2] 23 89 [2] 64 98 [2] 2a 94 [2] 26 9e [2] 31 95 [2] 2a db [2] 17 }

  condition:
    any of them
}