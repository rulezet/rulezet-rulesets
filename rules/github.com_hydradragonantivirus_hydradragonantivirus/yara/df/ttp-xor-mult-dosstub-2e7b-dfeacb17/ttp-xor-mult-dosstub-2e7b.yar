rule TTP_XOR_MULT_DOSStub_2e7b {
  strings:
    $key_2e7b = { 7a 13 [2] 0e 0b [2] 49 09 [2] 0e 18 [2] 40 14 [2] 4c 1e [2] 5b 15 [2] 40 5b [2] 7d }

  condition:
    any of them
}