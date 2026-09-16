rule TTP_XOR_MULT_DOSStub_8885 {
  strings:
    $key_8885 = { dc ed [2] a8 f5 [2] ef f7 [2] a8 e6 [2] e6 ea [2] ea e0 [2] fd eb [2] e6 a5 [2] db }

  condition:
    any of them
}