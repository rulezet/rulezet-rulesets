rule TTP_XOR_MULT_DOSStub_8886 {
  strings:
    $key_8886 = { dc ee [2] a8 f6 [2] ef f4 [2] a8 e5 [2] e6 e9 [2] ea e3 [2] fd e8 [2] e6 a6 [2] db }

  condition:
    any of them
}