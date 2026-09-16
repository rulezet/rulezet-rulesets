rule TTP_XOR_MULT_DOSStub_607b {
  strings:
    $key_607b = { 34 13 [2] 40 0b [2] 07 09 [2] 40 18 [2] 0e 14 [2] 02 1e [2] 15 15 [2] 0e 5b [2] 33 }

  condition:
    any of them
}