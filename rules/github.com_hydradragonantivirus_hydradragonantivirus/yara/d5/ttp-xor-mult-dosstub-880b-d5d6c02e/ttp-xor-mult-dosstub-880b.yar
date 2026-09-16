rule TTP_XOR_MULT_DOSStub_880b {
  strings:
    $key_880b = { dc 63 [2] a8 7b [2] ef 79 [2] a8 68 [2] e6 64 [2] ea 6e [2] fd 65 [2] e6 2b [2] db }

  condition:
    any of them
}