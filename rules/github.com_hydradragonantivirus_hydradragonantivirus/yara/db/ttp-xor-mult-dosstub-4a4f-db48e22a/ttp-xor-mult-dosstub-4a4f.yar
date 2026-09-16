rule TTP_XOR_MULT_DOSStub_4a4f {
  strings:
    $key_4a4f = { 1e 27 [2] 6a 3f [2] 2d 3d [2] 6a 2c [2] 24 20 [2] 28 2a [2] 3f 21 [2] 24 6f [2] 19 }

  condition:
    any of them
}