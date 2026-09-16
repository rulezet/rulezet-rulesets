rule TTP_XOR_MULT_DOSStub_674b {
  strings:
    $key_674b = { 33 23 [2] 47 3b [2] 00 39 [2] 47 28 [2] 09 24 [2] 05 2e [2] 12 25 [2] 09 6b [2] 34 }

  condition:
    any of them
}