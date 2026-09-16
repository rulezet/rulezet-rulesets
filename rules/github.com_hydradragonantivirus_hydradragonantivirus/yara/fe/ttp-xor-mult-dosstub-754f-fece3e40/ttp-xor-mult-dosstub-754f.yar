rule TTP_XOR_MULT_DOSStub_754f {
  strings:
    $key_754f = { 21 27 [2] 55 3f [2] 12 3d [2] 55 2c [2] 1b 20 [2] 17 2a [2] 00 21 [2] 1b 6f [2] 26 }

  condition:
    any of them
}