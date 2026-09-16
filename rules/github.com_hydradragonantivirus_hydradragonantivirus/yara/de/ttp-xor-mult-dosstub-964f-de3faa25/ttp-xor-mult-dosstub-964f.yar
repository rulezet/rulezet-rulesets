rule TTP_XOR_MULT_DOSStub_964f {
  strings:
    $key_964f = { c2 27 [2] b6 3f [2] f1 3d [2] b6 2c [2] f8 20 [2] f4 2a [2] e3 21 [2] f8 6f [2] c5 }

  condition:
    any of them
}