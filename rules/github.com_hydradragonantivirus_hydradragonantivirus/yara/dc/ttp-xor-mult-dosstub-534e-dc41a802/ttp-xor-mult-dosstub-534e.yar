rule TTP_XOR_MULT_DOSStub_534e {
  strings:
    $key_534e = { 07 26 [2] 73 3e [2] 34 3c [2] 73 2d [2] 3d 21 [2] 31 2b [2] 26 20 [2] 3d 6e [2] 00 }

  condition:
    any of them
}