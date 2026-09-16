rule TTP_XOR_MULT_DOSStub_265d {
  strings:
    $key_265d = { 72 35 [2] 06 2d [2] 41 2f [2] 06 3e [2] 48 32 [2] 44 38 [2] 53 33 [2] 48 7d [2] 75 }

  condition:
    any of them
}