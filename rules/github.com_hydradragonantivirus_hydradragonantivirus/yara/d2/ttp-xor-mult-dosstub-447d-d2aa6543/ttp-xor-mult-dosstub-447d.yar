rule TTP_XOR_MULT_DOSStub_447d {
  strings:
    $key_447d = { 10 15 [2] 64 0d [2] 23 0f [2] 64 1e [2] 2a 12 [2] 26 18 [2] 31 13 [2] 2a 5d [2] 17 }

  condition:
    any of them
}