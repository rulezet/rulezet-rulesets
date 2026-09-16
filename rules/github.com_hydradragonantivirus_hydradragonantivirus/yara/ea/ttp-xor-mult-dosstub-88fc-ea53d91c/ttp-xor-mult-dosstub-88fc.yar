rule TTP_XOR_MULT_DOSStub_88fc {
  strings:
    $key_88fc = { dc 94 [2] a8 8c [2] ef 8e [2] a8 9f [2] e6 93 [2] ea 99 [2] fd 92 [2] e6 dc [2] db }

  condition:
    any of them
}