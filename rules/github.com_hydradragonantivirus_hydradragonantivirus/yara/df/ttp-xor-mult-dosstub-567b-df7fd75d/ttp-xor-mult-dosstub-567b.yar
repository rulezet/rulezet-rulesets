rule TTP_XOR_MULT_DOSStub_567b {
  strings:
    $key_567b = { 02 13 [2] 76 0b [2] 31 09 [2] 76 18 [2] 38 14 [2] 34 1e [2] 23 15 [2] 38 5b [2] 05 }

  condition:
    any of them
}