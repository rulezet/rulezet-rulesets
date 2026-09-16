rule TTP_XOR_MULT_DOSStub_88f5 {
  strings:
    $key_88f5 = { dc 9d [2] a8 85 [2] ef 87 [2] a8 96 [2] e6 9a [2] ea 90 [2] fd 9b [2] e6 d5 [2] db }

  condition:
    any of them
}