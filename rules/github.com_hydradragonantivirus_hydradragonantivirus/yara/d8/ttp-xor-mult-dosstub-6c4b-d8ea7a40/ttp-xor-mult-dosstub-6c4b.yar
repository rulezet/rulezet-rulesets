rule TTP_XOR_MULT_DOSStub_6c4b {
  strings:
    $key_6c4b = { 38 23 [2] 4c 3b [2] 0b 39 [2] 4c 28 [2] 02 24 [2] 0e 2e [2] 19 25 [2] 02 6b [2] 3f }

  condition:
    any of them
}