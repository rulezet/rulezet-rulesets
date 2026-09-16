rule TTP_XOR_MULT_DOSStub_75fb {
  strings:
    $key_75fb = { 21 93 [2] 55 8b [2] 12 89 [2] 55 98 [2] 1b 94 [2] 17 9e [2] 00 95 [2] 1b db [2] 26 }

  condition:
    any of them
}