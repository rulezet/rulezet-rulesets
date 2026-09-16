rule TTP_XOR_MULT_DOSStub_3a1b {
  strings:
    $key_3a1b = { 6e 73 [2] 1a 6b [2] 5d 69 [2] 1a 78 [2] 54 74 [2] 58 7e [2] 4f 75 [2] 54 3b [2] 69 }

  condition:
    any of them
}