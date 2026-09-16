rule TTP_XOR_MULT_DOSStub_8815 {
  strings:
    $key_8815 = { dc 7d [2] a8 65 [2] ef 67 [2] a8 76 [2] e6 7a [2] ea 70 [2] fd 7b [2] e6 35 [2] db }

  condition:
    any of them
}