rule TTP_XOR_MULT_DOSStub_88ee {
  strings:
    $key_88ee = { dc 86 [2] a8 9e [2] ef 9c [2] a8 8d [2] e6 81 [2] ea 8b [2] fd 80 [2] e6 ce [2] db }

  condition:
    any of them
}