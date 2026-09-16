rule TTP_XOR_MULT_DOSStub_6f4b {
  strings:
    $key_6f4b = { 3b 23 [2] 4f 3b [2] 08 39 [2] 4f 28 [2] 01 24 [2] 0d 2e [2] 1a 25 [2] 01 6b [2] 3c }

  condition:
    any of them
}