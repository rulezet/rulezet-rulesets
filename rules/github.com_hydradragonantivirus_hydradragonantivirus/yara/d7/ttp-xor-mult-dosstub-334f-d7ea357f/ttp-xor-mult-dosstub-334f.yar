rule TTP_XOR_MULT_DOSStub_334f {
  strings:
    $key_334f = { 67 27 [2] 13 3f [2] 54 3d [2] 13 2c [2] 5d 20 [2] 51 2a [2] 46 21 [2] 5d 6f [2] 60 }

  condition:
    any of them
}