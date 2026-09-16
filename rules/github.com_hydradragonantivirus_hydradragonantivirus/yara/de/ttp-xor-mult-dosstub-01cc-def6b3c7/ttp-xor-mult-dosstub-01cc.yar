rule TTP_XOR_MULT_DOSStub_01cc {
  strings:
    $key_01cc = { 55 a4 [2] 21 bc [2] 66 be [2] 21 af [2] 6f a3 [2] 63 a9 [2] 74 a2 [2] 6f ec [2] 52 }

  condition:
    any of them
}