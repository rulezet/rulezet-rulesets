rule TTP_XOR_MULT_DOSStub_b14f {
  strings:
    $key_b14f = { e5 27 [2] 91 3f [2] d6 3d [2] 91 2c [2] df 20 [2] d3 2a [2] c4 21 [2] df 6f [2] e2 }

  condition:
    any of them
}