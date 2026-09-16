rule TTP_XOR_MULT_DOSStub_26cc {
  strings:
    $key_26cc = { 72 a4 [2] 06 bc [2] 41 be [2] 06 af [2] 48 a3 [2] 44 a9 [2] 53 a2 [2] 48 ec [2] 75 }

  condition:
    any of them
}