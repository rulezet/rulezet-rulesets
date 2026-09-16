rule TTP_XOR_MULT_DOSStub_8813 {
  strings:
    $key_8813 = { dc 7b [2] a8 63 [2] ef 61 [2] a8 70 [2] e6 7c [2] ea 76 [2] fd 7d [2] e6 33 [2] db }

  condition:
    any of them
}