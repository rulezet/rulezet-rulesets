rule TTP_XOR_MULT_DOSStub_411d {
  strings:
    $key_411d = { 15 75 [2] 61 6d [2] 26 6f [2] 61 7e [2] 2f 72 [2] 23 78 [2] 34 73 [2] 2f 3d [2] 12 }

  condition:
    any of them
}