rule TTP_XOR_MULT_DOSStub_7f4b {
  strings:
    $key_7f4b = { 2b 23 [2] 5f 3b [2] 18 39 [2] 5f 28 [2] 11 24 [2] 1d 2e [2] 0a 25 [2] 11 6b [2] 2c }

  condition:
    any of them
}