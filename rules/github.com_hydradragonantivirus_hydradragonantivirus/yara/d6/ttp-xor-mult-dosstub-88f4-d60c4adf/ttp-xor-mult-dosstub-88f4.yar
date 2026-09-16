rule TTP_XOR_MULT_DOSStub_88f4 {
  strings:
    $key_88f4 = { dc 9c [2] a8 84 [2] ef 86 [2] a8 97 [2] e6 9b [2] ea 91 [2] fd 9a [2] e6 d4 [2] db }

  condition:
    any of them
}