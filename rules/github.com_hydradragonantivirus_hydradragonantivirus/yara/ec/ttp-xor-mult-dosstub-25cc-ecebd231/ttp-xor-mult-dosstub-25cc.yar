rule TTP_XOR_MULT_DOSStub_25cc {
  strings:
    $key_25cc = { 71 a4 [2] 05 bc [2] 42 be [2] 05 af [2] 4b a3 [2] 47 a9 [2] 50 a2 [2] 4b ec [2] 76 }

  condition:
    any of them
}