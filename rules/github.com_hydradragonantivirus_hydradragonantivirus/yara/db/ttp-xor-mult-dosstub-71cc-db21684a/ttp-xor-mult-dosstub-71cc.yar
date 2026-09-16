rule TTP_XOR_MULT_DOSStub_71cc {
  strings:
    $key_71cc = { 25 a4 [2] 51 bc [2] 16 be [2] 51 af [2] 1f a3 [2] 13 a9 [2] 04 a2 [2] 1f ec [2] 22 }

  condition:
    any of them
}