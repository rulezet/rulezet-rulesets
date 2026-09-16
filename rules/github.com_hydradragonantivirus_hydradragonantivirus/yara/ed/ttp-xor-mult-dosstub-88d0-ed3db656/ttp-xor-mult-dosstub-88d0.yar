rule TTP_XOR_MULT_DOSStub_88d0 {
  strings:
    $key_88d0 = { dc b8 [2] a8 a0 [2] ef a2 [2] a8 b3 [2] e6 bf [2] ea b5 [2] fd be [2] e6 f0 [2] db }

  condition:
    any of them
}