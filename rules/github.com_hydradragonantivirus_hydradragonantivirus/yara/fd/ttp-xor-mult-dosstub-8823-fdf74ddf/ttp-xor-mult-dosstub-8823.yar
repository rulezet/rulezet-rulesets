rule TTP_XOR_MULT_DOSStub_8823 {
  strings:
    $key_8823 = { dc 4b [2] a8 53 [2] ef 51 [2] a8 40 [2] e6 4c [2] ea 46 [2] fd 4d [2] e6 03 [2] db }

  condition:
    any of them
}