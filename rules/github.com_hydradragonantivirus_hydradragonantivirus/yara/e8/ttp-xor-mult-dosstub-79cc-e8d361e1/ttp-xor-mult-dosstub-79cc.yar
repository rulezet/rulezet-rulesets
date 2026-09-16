rule TTP_XOR_MULT_DOSStub_79cc {
  strings:
    $key_79cc = { 2d a4 [2] 59 bc [2] 1e be [2] 59 af [2] 17 a3 [2] 1b a9 [2] 0c a2 [2] 17 ec [2] 2a }

  condition:
    any of them
}