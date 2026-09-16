rule TTP_XOR_MULT_DOSStub_204b {
  strings:
    $key_204b = { 74 23 [2] 00 3b [2] 47 39 [2] 00 28 [2] 4e 24 [2] 42 2e [2] 55 25 [2] 4e 6b [2] 73 }

  condition:
    any of them
}