rule TTP_XOR_MULT_DOSStub_8817 {
  strings:
    $key_8817 = { dc 7f [2] a8 67 [2] ef 65 [2] a8 74 [2] e6 78 [2] ea 72 [2] fd 79 [2] e6 37 [2] db }

  condition:
    any of them
}