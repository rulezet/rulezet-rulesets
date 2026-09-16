rule TTP_XOR_MULT_DOSStub_535d {
  strings:
    $key_535d = { 07 35 [2] 73 2d [2] 34 2f [2] 73 3e [2] 3d 32 [2] 31 38 [2] 26 33 [2] 3d 7d [2] 00 }

  condition:
    any of them
}