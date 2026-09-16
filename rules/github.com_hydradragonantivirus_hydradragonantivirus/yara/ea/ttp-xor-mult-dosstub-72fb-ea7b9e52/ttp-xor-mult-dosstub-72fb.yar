rule TTP_XOR_MULT_DOSStub_72fb {
  strings:
    $key_72fb = { 26 93 [2] 52 8b [2] 15 89 [2] 52 98 [2] 1c 94 [2] 10 9e [2] 07 95 [2] 1c db [2] 21 }

  condition:
    any of them
}