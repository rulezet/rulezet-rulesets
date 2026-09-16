rule TTP_XOR_MULT_DOSStub_645d {
  strings:
    $key_645d = { 30 35 [2] 44 2d [2] 03 2f [2] 44 3e [2] 0a 32 [2] 06 38 [2] 11 33 [2] 0a 7d [2] 37 }

  condition:
    any of them
}