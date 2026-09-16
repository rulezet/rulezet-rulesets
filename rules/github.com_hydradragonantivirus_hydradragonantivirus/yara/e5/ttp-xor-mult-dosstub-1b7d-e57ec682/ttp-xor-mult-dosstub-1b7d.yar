rule TTP_XOR_MULT_DOSStub_1b7d {
  strings:
    $key_1b7d = { 4f 15 [2] 3b 0d [2] 7c 0f [2] 3b 1e [2] 75 12 [2] 79 18 [2] 6e 13 [2] 75 5d [2] 48 }

  condition:
    any of them
}