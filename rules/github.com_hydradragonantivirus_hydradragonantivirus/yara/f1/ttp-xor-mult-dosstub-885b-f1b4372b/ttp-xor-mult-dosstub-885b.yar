rule TTP_XOR_MULT_DOSStub_885b {
  strings:
    $key_885b = { dc 33 [2] a8 2b [2] ef 29 [2] a8 38 [2] e6 34 [2] ea 3e [2] fd 35 [2] e6 7b [2] db }

  condition:
    any of them
}