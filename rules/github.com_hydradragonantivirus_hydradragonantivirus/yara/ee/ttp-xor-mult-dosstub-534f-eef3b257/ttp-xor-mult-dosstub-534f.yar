rule TTP_XOR_MULT_DOSStub_534f {
  strings:
    $key_534f = { 07 27 [2] 73 3f [2] 34 3d [2] 73 2c [2] 3d 20 [2] 31 2a [2] 26 21 [2] 3d 6f [2] 00 }

  condition:
    any of them
}