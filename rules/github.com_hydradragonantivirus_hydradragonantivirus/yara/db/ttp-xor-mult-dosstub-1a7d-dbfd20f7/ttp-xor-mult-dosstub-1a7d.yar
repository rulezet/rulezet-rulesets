rule TTP_XOR_MULT_DOSStub_1a7d {
  strings:
    $key_1a7d = { 4e 15 [2] 3a 0d [2] 7d 0f [2] 3a 1e [2] 74 12 [2] 78 18 [2] 6f 13 [2] 74 5d [2] 49 }

  condition:
    any of them
}