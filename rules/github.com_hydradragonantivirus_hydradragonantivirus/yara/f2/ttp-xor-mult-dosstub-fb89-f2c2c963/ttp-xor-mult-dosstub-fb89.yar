rule TTP_XOR_MULT_DOSStub_fb89 {
  strings:
    $key_fb89 = { af e1 [2] db f9 [2] 9c fb [2] db ea [2] 95 e6 [2] 99 ec [2] 8e e7 [2] 95 a9 [2] a8 }

  condition:
    any of them
}