rule TTP_XOR_MULT_DOSStub_001b {
  strings:
    $key_001b = { 54 73 [2] 20 6b [2] 67 69 [2] 20 78 [2] 6e 74 [2] 62 7e [2] 75 75 [2] 6e 3b [2] 53 }

  condition:
    any of them
}