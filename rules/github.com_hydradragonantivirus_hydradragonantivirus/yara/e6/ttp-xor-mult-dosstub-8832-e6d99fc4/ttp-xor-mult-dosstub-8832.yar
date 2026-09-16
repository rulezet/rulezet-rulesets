rule TTP_XOR_MULT_DOSStub_8832 {
  strings:
    $key_8832 = { dc 5a [2] a8 42 [2] ef 40 [2] a8 51 [2] e6 5d [2] ea 57 [2] fd 5c [2] e6 12 [2] db }

  condition:
    any of them
}