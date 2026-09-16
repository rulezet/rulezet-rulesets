rule TTP_XOR_MULT_DOSStub_15d9 {
  strings:
    $key_15d9 = { 41 b1 [2] 35 a9 [2] 72 ab [2] 35 ba [2] 7b b6 [2] 77 bc [2] 60 b7 [2] 7b f9 [2] 46 }

  condition:
    any of them
}