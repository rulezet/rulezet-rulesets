rule TTP_XOR_MULT_DOSStub_26d2 {
  strings:
    $key_26d2 = { 72 ba [2] 06 a2 [2] 41 a0 [2] 06 b1 [2] 48 bd [2] 44 b7 [2] 53 bc [2] 48 f2 [2] 75 }

  condition:
    any of them
}