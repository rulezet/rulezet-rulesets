rule TTP_XOR_MULT_DOSStub_88ce {
  strings:
    $key_88ce = { dc a6 [2] a8 be [2] ef bc [2] a8 ad [2] e6 a1 [2] ea ab [2] fd a0 [2] e6 ee [2] db }

  condition:
    any of them
}