rule TTP_XOR_MULT_DOSStub_034b {
  strings:
    $key_034b = { 57 23 [2] 23 3b [2] 64 39 [2] 23 28 [2] 6d 24 [2] 61 2e [2] 76 25 [2] 6d 6b [2] 50 }

  condition:
    any of them
}