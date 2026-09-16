rule TTP_XOR_MULT_DOSStub_4f4b {
  strings:
    $key_4f4b = { 1b 23 [2] 6f 3b [2] 28 39 [2] 6f 28 [2] 21 24 [2] 2d 2e [2] 3a 25 [2] 21 6b [2] 1c }

  condition:
    any of them
}