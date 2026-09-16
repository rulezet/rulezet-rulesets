rule TTP_XOR_MULT_DOSStub_43d9 {
  strings:
    $key_43d9 = { 17 b1 [2] 63 a9 [2] 24 ab [2] 63 ba [2] 2d b6 [2] 21 bc [2] 36 b7 [2] 2d f9 [2] 10 }

  condition:
    any of them
}