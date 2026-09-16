rule TTP_XOR_MULT_DOSStub_154b {
  strings:
    $key_154b = { 41 23 [2] 35 3b [2] 72 39 [2] 35 28 [2] 7b 24 [2] 77 2e [2] 60 25 [2] 7b 6b [2] 46 }

  condition:
    any of them
}