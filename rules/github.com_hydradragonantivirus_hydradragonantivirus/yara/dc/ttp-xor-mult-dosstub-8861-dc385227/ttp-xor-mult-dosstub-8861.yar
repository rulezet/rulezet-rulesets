rule TTP_XOR_MULT_DOSStub_8861 {
  strings:
    $key_8861 = { dc 09 [2] a8 11 [2] ef 13 [2] a8 02 [2] e6 0e [2] ea 04 [2] fd 0f [2] e6 41 [2] db }

  condition:
    any of them
}