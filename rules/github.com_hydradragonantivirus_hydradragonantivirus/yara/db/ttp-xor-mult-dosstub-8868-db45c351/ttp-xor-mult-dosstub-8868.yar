rule TTP_XOR_MULT_DOSStub_8868 {
  strings:
    $key_8868 = { dc 00 [2] a8 18 [2] ef 1a [2] a8 0b [2] e6 07 [2] ea 0d [2] fd 06 [2] e6 48 [2] db }

  condition:
    any of them
}