rule TTP_XOR_MULT_DOSStub_5a4e {
  strings:
    $key_5a4e = { 0e 26 [2] 7a 3e [2] 3d 3c [2] 7a 2d [2] 34 21 [2] 38 2b [2] 2f 20 [2] 34 6e [2] 09 }

  condition:
    any of them
}