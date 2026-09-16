rule TTP_XOR_MULT_DOSStub_f44b {
  strings:
    $key_f44b = { a0 23 [2] d4 3b [2] 93 39 [2] d4 28 [2] 9a 24 [2] 96 2e [2] 81 25 [2] 9a 6b [2] a7 }

  condition:
    any of them
}