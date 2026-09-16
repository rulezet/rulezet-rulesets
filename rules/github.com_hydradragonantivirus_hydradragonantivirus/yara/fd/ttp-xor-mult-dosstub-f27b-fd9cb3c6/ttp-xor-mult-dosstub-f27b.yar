rule TTP_XOR_MULT_DOSStub_f27b {
  strings:
    $key_f27b = { a6 13 [2] d2 0b [2] 95 09 [2] d2 18 [2] 9c 14 [2] 90 1e [2] 87 15 [2] 9c 5b [2] a1 }

  condition:
    any of them
}