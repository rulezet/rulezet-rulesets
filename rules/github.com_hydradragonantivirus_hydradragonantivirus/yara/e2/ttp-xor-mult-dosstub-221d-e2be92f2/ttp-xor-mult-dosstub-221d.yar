rule TTP_XOR_MULT_DOSStub_221d {
  strings:
    $key_221d = { 76 75 [2] 02 6d [2] 45 6f [2] 02 7e [2] 4c 72 [2] 40 78 [2] 57 73 [2] 4c 3d [2] 71 }

  condition:
    any of them
}