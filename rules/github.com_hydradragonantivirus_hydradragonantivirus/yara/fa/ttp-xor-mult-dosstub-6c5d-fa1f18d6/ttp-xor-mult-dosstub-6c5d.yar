rule TTP_XOR_MULT_DOSStub_6c5d {
  strings:
    $key_6c5d = { 38 35 [2] 4c 2d [2] 0b 2f [2] 4c 3e [2] 02 32 [2] 0e 38 [2] 19 33 [2] 02 7d [2] 3f }

  condition:
    any of them
}