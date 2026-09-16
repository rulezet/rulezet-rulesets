rule TTP_XOR_MULT_DOSStub_884f {
  strings:
    $key_884f = { dc 27 [2] a8 3f [2] ef 3d [2] a8 2c [2] e6 20 [2] ea 2a [2] fd 21 [2] e6 6f [2] db }

  condition:
    any of them
}