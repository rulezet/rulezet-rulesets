rule TTP_XOR_MULT_DOSStub_88c3 {
  strings:
    $key_88c3 = { dc ab [2] a8 b3 [2] ef b1 [2] a8 a0 [2] e6 ac [2] ea a6 [2] fd ad [2] e6 e3 [2] db }

  condition:
    any of them
}