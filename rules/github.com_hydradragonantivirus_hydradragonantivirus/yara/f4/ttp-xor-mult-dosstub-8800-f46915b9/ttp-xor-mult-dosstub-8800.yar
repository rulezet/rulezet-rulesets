rule TTP_XOR_MULT_DOSStub_8800 {
  strings:
    $key_8800 = { dc 68 [2] a8 70 [2] ef 72 [2] a8 63 [2] e6 6f [2] ea 65 [2] fd 6e [2] e6 20 [2] db }

  condition:
    any of them
}