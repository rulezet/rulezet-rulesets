rule TTP_XOR_MULT_DOSStub_761d {
  strings:
    $key_761d = { 22 75 [2] 56 6d [2] 11 6f [2] 56 7e [2] 18 72 [2] 14 78 [2] 03 73 [2] 18 3d [2] 25 }

  condition:
    any of them
}