rule TTP_XOR_MULT_DOSStub_8849 {
  strings:
    $key_8849 = { dc 21 [2] a8 39 [2] ef 3b [2] a8 2a [2] e6 26 [2] ea 2c [2] fd 27 [2] e6 69 [2] db }

  condition:
    any of them
}