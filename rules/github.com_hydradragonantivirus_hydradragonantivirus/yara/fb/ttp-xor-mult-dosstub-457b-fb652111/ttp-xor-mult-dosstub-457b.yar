rule TTP_XOR_MULT_DOSStub_457b {
  strings:
    $key_457b = { 11 13 [2] 65 0b [2] 22 09 [2] 65 18 [2] 2b 14 [2] 27 1e [2] 30 15 [2] 2b 5b [2] 16 }

  condition:
    any of them
}