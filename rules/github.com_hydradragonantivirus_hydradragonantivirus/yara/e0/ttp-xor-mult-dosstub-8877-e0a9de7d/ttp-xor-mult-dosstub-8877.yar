rule TTP_XOR_MULT_DOSStub_8877 {
  strings:
    $key_8877 = { dc 1f [2] a8 07 [2] ef 05 [2] a8 14 [2] e6 18 [2] ea 12 [2] fd 19 [2] e6 57 [2] db }

  condition:
    any of them
}