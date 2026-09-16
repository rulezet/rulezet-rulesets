rule TTP_XOR_MULT_DOSStub_585e {
  strings:
    $key_585e = { 0c 36 [2] 78 2e [2] 3f 2c [2] 78 3d [2] 36 31 [2] 3a 3b [2] 2d 30 [2] 36 7e [2] 0b }

  condition:
    any of them
}