rule TTP_XOR_MULT_DOSStub_8809 {
  strings:
    $key_8809 = { dc 61 [2] a8 79 [2] ef 7b [2] a8 6a [2] e6 66 [2] ea 6c [2] fd 67 [2] e6 29 [2] db }

  condition:
    any of them
}