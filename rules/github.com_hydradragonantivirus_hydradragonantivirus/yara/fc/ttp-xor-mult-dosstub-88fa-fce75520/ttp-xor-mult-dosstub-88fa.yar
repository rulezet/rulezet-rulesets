rule TTP_XOR_MULT_DOSStub_88fa {
  strings:
    $key_88fa = { dc 92 [2] a8 8a [2] ef 88 [2] a8 99 [2] e6 95 [2] ea 9f [2] fd 94 [2] e6 da [2] db }

  condition:
    any of them
}