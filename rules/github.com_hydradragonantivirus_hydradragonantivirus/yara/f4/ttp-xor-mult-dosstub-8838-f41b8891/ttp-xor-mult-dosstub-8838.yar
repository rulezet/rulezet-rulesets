rule TTP_XOR_MULT_DOSStub_8838 {
  strings:
    $key_8838 = { dc 50 [2] a8 48 [2] ef 4a [2] a8 5b [2] e6 57 [2] ea 5d [2] fd 56 [2] e6 18 [2] db }

  condition:
    any of them
}