rule TTP_XOR_MULT_DOSStub_a14f {
  strings:
    $key_a14f = { f5 27 [2] 81 3f [2] c6 3d [2] 81 2c [2] cf 20 [2] c3 2a [2] d4 21 [2] cf 6f [2] f2 }

  condition:
    any of them
}