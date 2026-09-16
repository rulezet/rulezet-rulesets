rule TTP_XOR_MULT_DOSStub_5f5d {
  strings:
    $key_5f5d = { 0b 35 [2] 7f 2d [2] 38 2f [2] 7f 3e [2] 31 32 [2] 3d 38 [2] 2a 33 [2] 31 7d [2] 0c }

  condition:
    any of them
}