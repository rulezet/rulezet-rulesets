rule TTP_XOR_MULT_DOSStub_12cc {
  strings:
    $key_12cc = { 46 a4 [2] 32 bc [2] 75 be [2] 32 af [2] 7c a3 [2] 70 a9 [2] 67 a2 [2] 7c ec [2] 41 }

  condition:
    any of them
}