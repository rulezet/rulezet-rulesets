rule TTP_XOR_MULT_DOSStub_12d9 {
  strings:
    $key_12d9 = { 46 b1 [2] 32 a9 [2] 75 ab [2] 32 ba [2] 7c b6 [2] 70 bc [2] 67 b7 [2] 7c f9 [2] 41 }

  condition:
    any of them
}