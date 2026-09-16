rule TTP_XOR_MULT_DOSStub_526d {
  strings:
    $key_526d = { 06 05 [2] 72 1d [2] 35 1f [2] 72 0e [2] 3c 02 [2] 30 08 [2] 27 03 [2] 3c 4d [2] 01 }

  condition:
    any of them
}