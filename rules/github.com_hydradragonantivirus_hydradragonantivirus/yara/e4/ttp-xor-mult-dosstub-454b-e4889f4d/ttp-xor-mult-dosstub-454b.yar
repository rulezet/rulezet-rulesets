rule TTP_XOR_MULT_DOSStub_454b {
  strings:
    $key_454b = { 11 23 [2] 65 3b [2] 22 39 [2] 65 28 [2] 2b 24 [2] 27 2e [2] 30 25 [2] 2b 6b [2] 16 }

  condition:
    any of them
}