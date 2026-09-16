rule TTP_XOR_MULT_DOSStub_885f {
  strings:
    $key_885f = { dc 37 [2] a8 2f [2] ef 2d [2] a8 3c [2] e6 30 [2] ea 3a [2] fd 31 [2] e6 7f [2] db }

  condition:
    any of them
}