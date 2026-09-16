rule TTP_XOR_MULT_DOSStub_62fb {
  strings:
    $key_62fb = { 36 93 [2] 42 8b [2] 05 89 [2] 42 98 [2] 0c 94 [2] 00 9e [2] 17 95 [2] 0c db [2] 31 }

  condition:
    any of them
}