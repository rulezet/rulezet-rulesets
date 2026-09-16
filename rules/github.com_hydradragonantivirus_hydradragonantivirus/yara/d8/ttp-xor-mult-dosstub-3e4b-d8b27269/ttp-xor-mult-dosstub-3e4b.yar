rule TTP_XOR_MULT_DOSStub_3e4b {
  strings:
    $key_3e4b = { 6a 23 [2] 1e 3b [2] 59 39 [2] 1e 28 [2] 50 24 [2] 5c 2e [2] 4b 25 [2] 50 6b [2] 6d }

  condition:
    any of them
}