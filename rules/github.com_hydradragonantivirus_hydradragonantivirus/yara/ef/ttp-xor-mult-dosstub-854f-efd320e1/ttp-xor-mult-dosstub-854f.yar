rule TTP_XOR_MULT_DOSStub_854f {
  strings:
    $key_854f = { d1 27 [2] a5 3f [2] e2 3d [2] a5 2c [2] eb 20 [2] e7 2a [2] f0 21 [2] eb 6f [2] d6 }

  condition:
    any of them
}