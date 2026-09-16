rule TTP_XOR_MULT_DOSStub_470b {
  strings:
    $key_470b = { 13 63 [2] 67 7b [2] 20 79 [2] 67 68 [2] 29 64 [2] 25 6e [2] 32 65 [2] 29 2b [2] 14 }

  condition:
    any of them
}