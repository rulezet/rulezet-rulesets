rule TTP_XOR_MULT_DOSStub_781d {
  strings:
    $key_781d = { 2c 75 [2] 58 6d [2] 1f 6f [2] 58 7e [2] 16 72 [2] 1a 78 [2] 0d 73 [2] 16 3d [2] 2b }

  condition:
    any of them
}