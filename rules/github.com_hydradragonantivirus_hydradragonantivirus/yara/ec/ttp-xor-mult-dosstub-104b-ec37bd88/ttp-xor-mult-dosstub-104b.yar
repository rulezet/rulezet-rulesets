rule TTP_XOR_MULT_DOSStub_104b {
  strings:
    $key_104b = { 44 23 [2] 30 3b [2] 77 39 [2] 30 28 [2] 7e 24 [2] 72 2e [2] 65 25 [2] 7e 6b [2] 43 }

  condition:
    any of them
}