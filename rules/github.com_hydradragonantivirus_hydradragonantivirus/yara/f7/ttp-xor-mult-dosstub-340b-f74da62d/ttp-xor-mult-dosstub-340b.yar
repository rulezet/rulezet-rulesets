rule TTP_XOR_MULT_DOSStub_340b {
  strings:
    $key_340b = { 60 63 [2] 14 7b [2] 53 79 [2] 14 68 [2] 5a 64 [2] 56 6e [2] 41 65 [2] 5a 2b [2] 67 }

  condition:
    any of them
}