rule TTP_XOR_MULT_DOSStub_8818 {
  strings:
    $key_8818 = { dc 70 [2] a8 68 [2] ef 6a [2] a8 7b [2] e6 77 [2] ea 7d [2] fd 76 [2] e6 38 [2] db }

  condition:
    any of them
}