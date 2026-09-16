rule TTP_XOR_MULT_DOSStub_604f {
  strings:
    $key_604f = { 34 27 [2] 40 3f [2] 07 3d [2] 40 2c [2] 0e 20 [2] 02 2a [2] 15 21 [2] 0e 6f [2] 33 }

  condition:
    any of them
}