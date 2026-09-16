rule TTP_XOR_MULT_DOSStub_8824 {
  strings:
    $key_8824 = { dc 4c [2] a8 54 [2] ef 56 [2] a8 47 [2] e6 4b [2] ea 41 [2] fd 4a [2] e6 04 [2] db }

  condition:
    any of them
}