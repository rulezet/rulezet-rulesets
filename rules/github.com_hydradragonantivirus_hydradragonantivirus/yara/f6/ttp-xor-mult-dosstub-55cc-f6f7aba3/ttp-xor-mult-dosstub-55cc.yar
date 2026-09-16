rule TTP_XOR_MULT_DOSStub_55cc {
  strings:
    $key_55cc = { 01 a4 [2] 75 bc [2] 32 be [2] 75 af [2] 3b a3 [2] 37 a9 [2] 20 a2 [2] 3b ec [2] 06 }

  condition:
    any of them
}