rule TTP_XOR_MULT_DOSStub_441d {
  strings:
    $key_441d = { 10 75 [2] 64 6d [2] 23 6f [2] 64 7e [2] 2a 72 [2] 26 78 [2] 31 73 [2] 2a 3d [2] 17 }

  condition:
    any of them
}