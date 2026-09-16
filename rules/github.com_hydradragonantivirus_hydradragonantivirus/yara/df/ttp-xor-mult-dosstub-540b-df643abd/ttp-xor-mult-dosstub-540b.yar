rule TTP_XOR_MULT_DOSStub_540b {
  strings:
    $key_540b = { 00 63 [2] 74 7b [2] 33 79 [2] 74 68 [2] 3a 64 [2] 36 6e [2] 21 65 [2] 3a 2b [2] 07 }

  condition:
    any of them
}