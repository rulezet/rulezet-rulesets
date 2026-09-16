rule TTP_XOR_MULT_DOSStub_740b {
  strings:
    $key_740b = { 20 63 [2] 54 7b [2] 13 79 [2] 54 68 [2] 1a 64 [2] 16 6e [2] 01 65 [2] 1a 2b [2] 27 }

  condition:
    any of them
}