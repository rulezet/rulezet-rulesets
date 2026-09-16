rule TTP_XOR_MULT_DOSStub_3a4d {
  strings:
    $key_3a4d = { 6e 25 [2] 1a 3d [2] 5d 3f [2] 1a 2e [2] 54 22 [2] 58 28 [2] 4f 23 [2] 54 6d [2] 69 }

  condition:
    any of them
}