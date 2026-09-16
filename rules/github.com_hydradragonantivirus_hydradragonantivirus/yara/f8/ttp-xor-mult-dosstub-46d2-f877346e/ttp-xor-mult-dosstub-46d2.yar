rule TTP_XOR_MULT_DOSStub_46d2 {
  strings:
    $key_46d2 = { 12 ba [2] 66 a2 [2] 21 a0 [2] 66 b1 [2] 28 bd [2] 24 b7 [2] 33 bc [2] 28 f2 [2] 15 }

  condition:
    any of them
}