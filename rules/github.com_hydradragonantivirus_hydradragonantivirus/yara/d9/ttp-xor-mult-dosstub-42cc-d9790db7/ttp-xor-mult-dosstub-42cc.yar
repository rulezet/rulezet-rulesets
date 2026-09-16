rule TTP_XOR_MULT_DOSStub_42cc {
  strings:
    $key_42cc = { 16 a4 [2] 62 bc [2] 25 be [2] 62 af [2] 2c a3 [2] 20 a9 [2] 37 a2 [2] 2c ec [2] 11 }

  condition:
    any of them
}