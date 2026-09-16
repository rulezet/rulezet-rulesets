rule TTP_XOR_MULT_DOSStub_430b {
  strings:
    $key_430b = { 17 63 [2] 63 7b [2] 24 79 [2] 63 68 [2] 2d 64 [2] 21 6e [2] 36 65 [2] 2d 2b [2] 10 }

  condition:
    any of them
}