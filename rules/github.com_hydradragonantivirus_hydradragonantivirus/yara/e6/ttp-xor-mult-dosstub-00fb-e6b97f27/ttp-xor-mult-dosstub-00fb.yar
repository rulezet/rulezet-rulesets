rule TTP_XOR_MULT_DOSStub_00fb {
  strings:
    $key_00fb = { 54 93 [2] 20 8b [2] 67 89 [2] 20 98 [2] 6e 94 [2] 62 9e [2] 75 95 [2] 6e db [2] 53 }

  condition:
    any of them
}