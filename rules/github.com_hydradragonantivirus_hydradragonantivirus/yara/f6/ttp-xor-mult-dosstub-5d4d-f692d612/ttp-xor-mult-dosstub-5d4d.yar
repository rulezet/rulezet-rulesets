rule TTP_XOR_MULT_DOSStub_5d4d {
  strings:
    $key_5d4d = { 09 25 [2] 7d 3d [2] 3a 3f [2] 7d 2e [2] 33 22 [2] 3f 28 [2] 28 23 [2] 33 6d [2] 0e }

  condition:
    any of them
}