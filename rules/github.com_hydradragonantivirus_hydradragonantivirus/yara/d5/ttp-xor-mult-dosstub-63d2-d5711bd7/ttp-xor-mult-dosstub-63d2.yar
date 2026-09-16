rule TTP_XOR_MULT_DOSStub_63d2 {
  strings:
    $key_63d2 = { 37 ba [2] 43 a2 [2] 04 a0 [2] 43 b1 [2] 0d bd [2] 01 b7 [2] 16 bc [2] 0d f2 [2] 30 }

  condition:
    any of them
}