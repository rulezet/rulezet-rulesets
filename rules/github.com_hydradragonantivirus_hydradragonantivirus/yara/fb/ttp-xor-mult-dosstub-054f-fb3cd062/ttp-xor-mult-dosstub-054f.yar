rule TTP_XOR_MULT_DOSStub_054f {
  strings:
    $key_054f = { 51 27 [2] 25 3f [2] 62 3d [2] 25 2c [2] 6b 20 [2] 67 2a [2] 70 21 [2] 6b 6f [2] 56 }

  condition:
    any of them
}