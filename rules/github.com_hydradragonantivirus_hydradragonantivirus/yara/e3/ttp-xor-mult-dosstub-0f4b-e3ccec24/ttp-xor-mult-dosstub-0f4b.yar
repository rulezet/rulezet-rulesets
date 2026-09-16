rule TTP_XOR_MULT_DOSStub_0f4b {
  strings:
    $key_0f4b = { 5b 23 [2] 2f 3b [2] 68 39 [2] 2f 28 [2] 61 24 [2] 6d 2e [2] 7a 25 [2] 61 6b [2] 5c }

  condition:
    any of them
}