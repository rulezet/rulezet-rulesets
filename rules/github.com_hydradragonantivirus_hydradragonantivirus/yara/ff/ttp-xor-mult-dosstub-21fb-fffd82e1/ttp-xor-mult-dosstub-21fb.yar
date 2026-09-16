rule TTP_XOR_MULT_DOSStub_21fb {
  strings:
    $key_21fb = { 75 93 [2] 01 8b [2] 46 89 [2] 01 98 [2] 4f 94 [2] 43 9e [2] 54 95 [2] 4f db [2] 72 }

  condition:
    any of them
}