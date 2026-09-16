rule TTP_XOR_MULT_DOSStub_4282 {
  strings:
    $key_4282 = { 16 ea [2] 62 f2 [2] 25 f0 [2] 62 e1 [2] 2c ed [2] 20 e7 [2] 37 ec [2] 2c a2 [2] 11 }

  condition:
    any of them
}