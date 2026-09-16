rule TTP_XOR_MULT_DOSStub_8801 {
  strings:
    $key_8801 = { dc 69 [2] a8 71 [2] ef 73 [2] a8 62 [2] e6 6e [2] ea 64 [2] fd 6f [2] e6 21 [2] db }

  condition:
    any of them
}