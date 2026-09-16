rule TTP_XOR_MULT_DOSStub_88e8 {
  strings:
    $key_88e8 = { dc 80 [2] a8 98 [2] ef 9a [2] a8 8b [2] e6 87 [2] ea 8d [2] fd 86 [2] e6 c8 [2] db }

  condition:
    any of them
}