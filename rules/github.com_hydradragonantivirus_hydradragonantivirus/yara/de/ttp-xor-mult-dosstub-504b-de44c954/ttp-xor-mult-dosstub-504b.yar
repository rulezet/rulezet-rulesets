rule TTP_XOR_MULT_DOSStub_504b {
  strings:
    $key_504b = { 04 23 [2] 70 3b [2] 37 39 [2] 70 28 [2] 3e 24 [2] 32 2e [2] 25 25 [2] 3e 6b [2] 03 }

  condition:
    any of them
}