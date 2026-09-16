rule TTP_XOR_MULT_DOSStub_88bd {
  strings:
    $key_88bd = { dc d5 [2] a8 cd [2] ef cf [2] a8 de [2] e6 d2 [2] ea d8 [2] fd d3 [2] e6 9d [2] db }

  condition:
    any of them
}