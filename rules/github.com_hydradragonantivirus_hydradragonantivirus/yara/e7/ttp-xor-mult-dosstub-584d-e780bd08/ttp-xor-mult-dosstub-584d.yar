rule TTP_XOR_MULT_DOSStub_584d {
  strings:
    $key_584d = { 0c 25 [2] 78 3d [2] 3f 3f [2] 78 2e [2] 36 22 [2] 3a 28 [2] 2d 23 [2] 36 6d [2] 0b }

  condition:
    any of them
}