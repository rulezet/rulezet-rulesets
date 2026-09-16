rule TTP_XOR_MULT_DOSStub_751d {
  strings:
    $key_751d = { 21 75 [2] 55 6d [2] 12 6f [2] 55 7e [2] 1b 72 [2] 17 78 [2] 00 73 [2] 1b 3d [2] 26 }

  condition:
    any of them
}