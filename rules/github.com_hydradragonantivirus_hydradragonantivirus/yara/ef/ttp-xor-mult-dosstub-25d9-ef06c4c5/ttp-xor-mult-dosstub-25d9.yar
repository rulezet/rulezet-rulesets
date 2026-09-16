rule TTP_XOR_MULT_DOSStub_25d9 {
  strings:
    $key_25d9 = { 71 b1 [2] 05 a9 [2] 42 ab [2] 05 ba [2] 4b b6 [2] 47 bc [2] 50 b7 [2] 4b f9 [2] 76 }

  condition:
    any of them
}