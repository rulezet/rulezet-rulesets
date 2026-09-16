rule TTP_XOR_MULT_DOSStub_547d {
  strings:
    $key_547d = { 00 15 [2] 74 0d [2] 33 0f [2] 74 1e [2] 3a 12 [2] 36 18 [2] 21 13 [2] 3a 5d [2] 07 }

  condition:
    any of them
}