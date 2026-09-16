rule TTP_XOR_MULT_DOSStub_dd4f {
  strings:
    $key_dd4f = { 89 27 [2] fd 3f [2] ba 3d [2] fd 2c [2] b3 20 [2] bf 2a [2] a8 21 [2] b3 6f [2] 8e }

  condition:
    any of them
}