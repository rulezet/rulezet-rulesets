rule TTP_XOR_MULT_DOSStub_531d {
  strings:
    $key_531d = { 07 75 [2] 73 6d [2] 34 6f [2] 73 7e [2] 3d 72 [2] 31 78 [2] 26 73 [2] 3d 3d [2] 00 }

  condition:
    any of them
}