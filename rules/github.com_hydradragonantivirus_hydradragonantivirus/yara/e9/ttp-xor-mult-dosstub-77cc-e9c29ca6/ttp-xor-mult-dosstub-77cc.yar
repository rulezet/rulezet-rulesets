rule TTP_XOR_MULT_DOSStub_77cc {
  strings:
    $key_77cc = { 23 a4 [2] 57 bc [2] 10 be [2] 57 af [2] 19 a3 [2] 15 a9 [2] 02 a2 [2] 19 ec [2] 24 }

  condition:
    any of them
}