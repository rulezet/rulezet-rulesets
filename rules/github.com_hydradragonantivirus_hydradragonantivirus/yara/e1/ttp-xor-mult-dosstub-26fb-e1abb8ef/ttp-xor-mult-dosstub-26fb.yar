rule TTP_XOR_MULT_DOSStub_26fb {
  strings:
    $key_26fb = { 72 93 [2] 06 8b [2] 41 89 [2] 06 98 [2] 48 94 [2] 44 9e [2] 53 95 [2] 48 db [2] 75 }

  condition:
    any of them
}