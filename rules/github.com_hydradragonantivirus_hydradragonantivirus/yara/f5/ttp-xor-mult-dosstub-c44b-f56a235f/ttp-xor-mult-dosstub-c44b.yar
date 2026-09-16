rule TTP_XOR_MULT_DOSStub_c44b {
  strings:
    $key_c44b = { 90 23 [2] e4 3b [2] a3 39 [2] e4 28 [2] aa 24 [2] a6 2e [2] b1 25 [2] aa 6b [2] 97 }

  condition:
    any of them
}