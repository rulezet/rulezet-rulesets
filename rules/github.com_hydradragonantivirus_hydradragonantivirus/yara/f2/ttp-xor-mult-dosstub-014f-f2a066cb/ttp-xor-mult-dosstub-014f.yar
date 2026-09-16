rule TTP_XOR_MULT_DOSStub_014f {
  strings:
    $key_014f = { 55 27 [2] 21 3f [2] 66 3d [2] 21 2c [2] 6f 20 [2] 63 2a [2] 74 21 [2] 6f 6f [2] 52 }

  condition:
    any of them
}