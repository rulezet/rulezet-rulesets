rule TTP_XOR_MULT_DOSStub_2d4f {
  strings:
    $key_2d4f = { 79 27 [2] 0d 3f [2] 4a 3d [2] 0d 2c [2] 43 20 [2] 4f 2a [2] 58 21 [2] 43 6f [2] 7e }

  condition:
    any of them
}