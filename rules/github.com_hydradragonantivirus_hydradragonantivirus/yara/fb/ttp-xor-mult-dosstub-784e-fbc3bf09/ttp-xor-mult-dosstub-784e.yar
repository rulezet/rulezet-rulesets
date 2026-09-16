rule TTP_XOR_MULT_DOSStub_784e {
  strings:
    $key_784e = { 2c 26 [2] 58 3e [2] 1f 3c [2] 58 2d [2] 16 21 [2] 1a 2b [2] 0d 20 [2] 16 6e [2] 2b }

  condition:
    any of them
}