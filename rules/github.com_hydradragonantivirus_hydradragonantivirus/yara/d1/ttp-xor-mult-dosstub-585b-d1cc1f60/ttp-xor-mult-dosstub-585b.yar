rule TTP_XOR_MULT_DOSStub_585b {
  strings:
    $key_585b = { 0c 33 [2] 78 2b [2] 3f 29 [2] 78 38 [2] 36 34 [2] 3a 3e [2] 2d 35 [2] 36 7b [2] 0b }

  condition:
    any of them
}