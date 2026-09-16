rule TTP_XOR_MULT_DOSStub_f04b {
  strings:
    $key_f04b = { a4 23 [2] d0 3b [2] 97 39 [2] d0 28 [2] 9e 24 [2] 92 2e [2] 85 25 [2] 9e 6b [2] a3 }

  condition:
    any of them
}