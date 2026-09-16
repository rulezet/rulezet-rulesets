rule TTP_XOR_MULT_DOSStub_5a4f {
  strings:
    $key_5a4f = { 0e 27 [2] 7a 3f [2] 3d 3d [2] 7a 2c [2] 34 20 [2] 38 2a [2] 2f 21 [2] 34 6f [2] 09 }

  condition:
    any of them
}