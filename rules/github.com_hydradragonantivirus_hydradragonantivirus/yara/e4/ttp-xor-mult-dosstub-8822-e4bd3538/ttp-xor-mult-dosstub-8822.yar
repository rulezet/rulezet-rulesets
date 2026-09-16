rule TTP_XOR_MULT_DOSStub_8822 {
  strings:
    $key_8822 = { dc 4a [2] a8 52 [2] ef 50 [2] a8 41 [2] e6 4d [2] ea 47 [2] fd 4c [2] e6 02 [2] db }

  condition:
    any of them
}