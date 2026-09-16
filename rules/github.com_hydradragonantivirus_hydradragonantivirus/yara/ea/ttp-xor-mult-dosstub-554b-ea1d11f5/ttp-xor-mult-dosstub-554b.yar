rule TTP_XOR_MULT_DOSStub_554b {
  strings:
    $key_554b = { 01 23 [2] 75 3b [2] 32 39 [2] 75 28 [2] 3b 24 [2] 37 2e [2] 20 25 [2] 3b 6b [2] 06 }

  condition:
    any of them
}