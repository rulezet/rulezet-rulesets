rule TTP_XOR_MULT_DOSStub_7c4d {
  strings:
    $key_7c4d = { 28 25 [2] 5c 3d [2] 1b 3f [2] 5c 2e [2] 12 22 [2] 1e 28 [2] 09 23 [2] 12 6d [2] 2f }

  condition:
    any of them
}