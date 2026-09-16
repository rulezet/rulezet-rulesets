rule TTP_XOR_MULT_DOSStub_32d9 {
  strings:
    $key_32d9 = { 66 b1 [2] 12 a9 [2] 55 ab [2] 12 ba [2] 5c b6 [2] 50 bc [2] 47 b7 [2] 5c f9 [2] 61 }

  condition:
    any of them
}