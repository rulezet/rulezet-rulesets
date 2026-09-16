rule TTP_XOR_MULT_DOSStub_5e7b {
  strings:
    $key_5e7b = { 0a 13 [2] 7e 0b [2] 39 09 [2] 7e 18 [2] 30 14 [2] 3c 1e [2] 2b 15 [2] 30 5b [2] 0d }

  condition:
    any of them
}