rule TTP_XOR_MULT_DOSStub_587b {
  strings:
    $key_587b = { 0c 13 [2] 78 0b [2] 3f 09 [2] 78 18 [2] 36 14 [2] 3a 1e [2] 2d 15 [2] 36 5b [2] 0b }

  condition:
    any of them
}