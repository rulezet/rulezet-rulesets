rule TTP_XOR_MULT_DOSStub_11cc {
  strings:
    $key_11cc = { 45 a4 [2] 31 bc [2] 76 be [2] 31 af [2] 7f a3 [2] 73 a9 [2] 64 a2 [2] 7f ec [2] 42 }

  condition:
    any of them
}