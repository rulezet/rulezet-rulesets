rule TTP_XOR_MULT_DOSStub_8851 {
  strings:
    $key_8851 = { dc 39 [2] a8 21 [2] ef 23 [2] a8 32 [2] e6 3e [2] ea 34 [2] fd 3f [2] e6 71 [2] db }

  condition:
    any of them
}