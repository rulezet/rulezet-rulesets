rule TTP_XOR_MULT_DOSStub_465d {
  strings:
    $key_465d = { 12 35 [2] 66 2d [2] 21 2f [2] 66 3e [2] 28 32 [2] 24 38 [2] 33 33 [2] 28 7d [2] 15 }

  condition:
    any of them
}