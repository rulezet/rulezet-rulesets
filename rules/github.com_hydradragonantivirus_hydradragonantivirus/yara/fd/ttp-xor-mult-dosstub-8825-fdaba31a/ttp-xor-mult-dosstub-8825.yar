rule TTP_XOR_MULT_DOSStub_8825 {
  strings:
    $key_8825 = { dc 4d [2] a8 55 [2] ef 57 [2] a8 46 [2] e6 4a [2] ea 40 [2] fd 4b [2] e6 05 [2] db }

  condition:
    any of them
}