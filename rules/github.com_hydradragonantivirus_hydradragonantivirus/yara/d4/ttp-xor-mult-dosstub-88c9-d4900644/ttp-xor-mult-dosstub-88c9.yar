rule TTP_XOR_MULT_DOSStub_88c9 {
  strings:
    $key_88c9 = { dc a1 [2] a8 b9 [2] ef bb [2] a8 aa [2] e6 a6 [2] ea ac [2] fd a7 [2] e6 e9 [2] db }

  condition:
    any of them
}