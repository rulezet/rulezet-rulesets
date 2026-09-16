rule TTP_XOR_MULT_DOSStub_36d2 {
  strings:
    $key_36d2 = { 62 ba [2] 16 a2 [2] 51 a0 [2] 16 b1 [2] 58 bd [2] 54 b7 [2] 43 bc [2] 58 f2 [2] 65 }

  condition:
    any of them
}