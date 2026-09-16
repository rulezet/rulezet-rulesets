rule TTP_XOR_MULT_DOSStub_8858 {
  strings:
    $key_8858 = { dc 30 [2] a8 28 [2] ef 2a [2] a8 3b [2] e6 37 [2] ea 3d [2] fd 36 [2] e6 78 [2] db }

  condition:
    any of them
}