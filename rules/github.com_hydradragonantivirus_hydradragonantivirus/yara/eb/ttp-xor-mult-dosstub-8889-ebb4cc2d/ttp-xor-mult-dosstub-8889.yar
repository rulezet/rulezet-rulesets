rule TTP_XOR_MULT_DOSStub_8889 {
  strings:
    $key_8889 = { dc e1 [2] a8 f9 [2] ef fb [2] a8 ea [2] e6 e6 [2] ea ec [2] fd e7 [2] e6 a9 [2] db }

  condition:
    any of them
}