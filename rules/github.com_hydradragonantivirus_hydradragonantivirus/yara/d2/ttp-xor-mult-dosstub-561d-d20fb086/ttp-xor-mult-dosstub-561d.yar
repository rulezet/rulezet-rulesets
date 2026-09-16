rule TTP_XOR_MULT_DOSStub_561d {
  strings:
    $key_561d = { 02 75 [2] 76 6d [2] 31 6f [2] 76 7e [2] 38 72 [2] 34 78 [2] 23 73 [2] 38 3d [2] 05 }

  condition:
    any of them
}