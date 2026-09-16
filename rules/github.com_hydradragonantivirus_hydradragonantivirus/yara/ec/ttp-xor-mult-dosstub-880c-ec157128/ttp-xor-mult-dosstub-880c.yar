rule TTP_XOR_MULT_DOSStub_880c {
  strings:
    $key_880c = { dc 64 [2] a8 7c [2] ef 7e [2] a8 6f [2] e6 63 [2] ea 69 [2] fd 62 [2] e6 2c [2] db }

  condition:
    any of them
}