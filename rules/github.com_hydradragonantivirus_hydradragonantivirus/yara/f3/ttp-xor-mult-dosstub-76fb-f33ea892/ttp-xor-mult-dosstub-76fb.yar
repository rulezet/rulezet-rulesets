rule TTP_XOR_MULT_DOSStub_76fb {
  strings:
    $key_76fb = { 22 93 [2] 56 8b [2] 11 89 [2] 56 98 [2] 18 94 [2] 14 9e [2] 03 95 [2] 18 db [2] 25 }

  condition:
    any of them
}