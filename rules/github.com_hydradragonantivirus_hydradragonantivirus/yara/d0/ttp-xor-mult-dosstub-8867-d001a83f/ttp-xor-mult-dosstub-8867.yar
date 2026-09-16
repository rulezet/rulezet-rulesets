rule TTP_XOR_MULT_DOSStub_8867 {
  strings:
    $key_8867 = { dc 0f [2] a8 17 [2] ef 15 [2] a8 04 [2] e6 08 [2] ea 02 [2] fd 09 [2] e6 47 [2] db }

  condition:
    any of them
}