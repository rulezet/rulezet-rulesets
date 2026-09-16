rule TTP_XOR_MULT_DOSStub_644d {
  strings:
    $key_644d = { 30 25 [2] 44 3d [2] 03 3f [2] 44 2e [2] 0a 22 [2] 06 28 [2] 11 23 [2] 0a 6d [2] 37 }

  condition:
    any of them
}