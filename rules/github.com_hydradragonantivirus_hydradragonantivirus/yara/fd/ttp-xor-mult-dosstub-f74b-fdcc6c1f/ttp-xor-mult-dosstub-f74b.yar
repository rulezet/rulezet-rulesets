rule TTP_XOR_MULT_DOSStub_f74b {
  strings:
    $key_f74b = { a3 23 [2] d7 3b [2] 90 39 [2] d7 28 [2] 99 24 [2] 95 2e [2] 82 25 [2] 99 6b [2] a4 }

  condition:
    any of them
}