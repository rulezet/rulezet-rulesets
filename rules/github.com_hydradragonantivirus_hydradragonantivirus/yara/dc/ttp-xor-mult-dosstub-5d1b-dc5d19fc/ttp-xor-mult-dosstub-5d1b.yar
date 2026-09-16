rule TTP_XOR_MULT_DOSStub_5d1b {
  strings:
    $key_5d1b = { 09 73 [2] 7d 6b [2] 3a 69 [2] 7d 78 [2] 33 74 [2] 3f 7e [2] 28 75 [2] 33 3b [2] 0e }

  condition:
    any of them
}