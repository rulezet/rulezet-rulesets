rule TTP_XOR_MULT_DOSStub_4ae6 {
  strings:
    $key_4ae6 = { 1e 8e [2] 6a 96 [2] 2d 94 [2] 6a 85 [2] 24 89 [2] 28 83 [2] 3f 88 [2] 24 c6 [2] 19 }

  condition:
    any of them
}