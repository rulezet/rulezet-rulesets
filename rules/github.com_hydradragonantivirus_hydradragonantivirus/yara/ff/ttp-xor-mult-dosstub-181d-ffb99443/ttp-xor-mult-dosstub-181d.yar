rule TTP_XOR_MULT_DOSStub_181d {
  strings:
    $key_181d = { 4c 75 [2] 38 6d [2] 7f 6f [2] 38 7e [2] 76 72 [2] 7a 78 [2] 6d 73 [2] 76 3d [2] 4b }

  condition:
    any of them
}