rule TTP_XOR_MULT_DOSStub_551d {
  strings:
    $key_551d = { 01 75 [2] 75 6d [2] 32 6f [2] 75 7e [2] 3b 72 [2] 37 78 [2] 20 73 [2] 3b 3d [2] 06 }

  condition:
    any of them
}