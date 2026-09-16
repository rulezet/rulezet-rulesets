rule TTP_XOR_MULT_DOSStub_78cc {
  strings:
    $key_78cc = { 2c a4 [2] 58 bc [2] 1f be [2] 58 af [2] 16 a3 [2] 1a a9 [2] 0d a2 [2] 16 ec [2] 2b }

  condition:
    any of them
}