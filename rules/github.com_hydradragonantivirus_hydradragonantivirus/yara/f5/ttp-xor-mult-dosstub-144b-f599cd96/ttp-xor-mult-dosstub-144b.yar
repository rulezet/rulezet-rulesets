rule TTP_XOR_MULT_DOSStub_144b {
  strings:
    $key_144b = { 40 23 [2] 34 3b [2] 73 39 [2] 34 28 [2] 7a 24 [2] 76 2e [2] 61 25 [2] 7a 6b [2] 47 }

  condition:
    any of them
}