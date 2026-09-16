rule TTP_XOR_MULT_DOSStub_883b {
  strings:
    $key_883b = { dc 53 [2] a8 4b [2] ef 49 [2] a8 58 [2] e6 54 [2] ea 5e [2] fd 55 [2] e6 1b [2] db }

  condition:
    any of them
}