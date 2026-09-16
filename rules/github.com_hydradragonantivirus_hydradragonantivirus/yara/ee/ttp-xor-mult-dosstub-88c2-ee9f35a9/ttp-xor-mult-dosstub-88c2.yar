rule TTP_XOR_MULT_DOSStub_88c2 {
  strings:
    $key_88c2 = { dc aa [2] a8 b2 [2] ef b0 [2] a8 a1 [2] e6 ad [2] ea a7 [2] fd ac [2] e6 e2 [2] db }

  condition:
    any of them
}