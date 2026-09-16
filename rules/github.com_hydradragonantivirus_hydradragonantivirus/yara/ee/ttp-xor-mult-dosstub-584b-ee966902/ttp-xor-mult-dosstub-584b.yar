rule TTP_XOR_MULT_DOSStub_584b {
  strings:
    $key_584b = { 0c 23 [2] 78 3b [2] 3f 39 [2] 78 28 [2] 36 24 [2] 3a 2e [2] 2d 25 [2] 36 6b [2] 0b }

  condition:
    any of them
}