rule TTP_XOR_MULT_DOSStub_cad8 {
  strings:
    $key_cad8 = { 9e b0 [2] ea a8 [2] ad aa [2] ea bb [2] a4 b7 [2] a8 bd [2] bf b6 [2] a4 f8 [2] 99 }

  condition:
    any of them
}