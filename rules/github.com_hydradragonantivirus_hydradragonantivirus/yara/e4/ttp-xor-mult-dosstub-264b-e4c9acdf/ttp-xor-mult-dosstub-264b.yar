rule TTP_XOR_MULT_DOSStub_264b {
  strings:
    $key_264b = { 72 23 [2] 06 3b [2] 41 39 [2] 06 28 [2] 48 24 [2] 44 2e [2] 53 25 [2] 48 6b [2] 75 }

  condition:
    any of them
}