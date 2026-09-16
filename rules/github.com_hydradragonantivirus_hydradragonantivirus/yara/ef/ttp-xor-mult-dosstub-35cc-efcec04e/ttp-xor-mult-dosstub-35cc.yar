rule TTP_XOR_MULT_DOSStub_35cc {
  strings:
    $key_35cc = { 61 a4 [2] 15 bc [2] 52 be [2] 15 af [2] 5b a3 [2] 57 a9 [2] 40 a2 [2] 5b ec [2] 66 }

  condition:
    any of them
}