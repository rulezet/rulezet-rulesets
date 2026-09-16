rule TTP_XOR_MULT_DOSStub_711d {
  strings:
    $key_711d = { 25 75 [2] 51 6d [2] 16 6f [2] 51 7e [2] 1f 72 [2] 13 78 [2] 04 73 [2] 1f 3d [2] 22 }

  condition:
    any of them
}