rule TTP_XOR_MULT_DOSStub_d4cc {
  strings:
    $key_d4cc = { 80 a4 [2] f4 bc [2] b3 be [2] f4 af [2] ba a3 [2] b6 a9 [2] a1 a2 [2] ba ec [2] 87 }

  condition:
    any of them
}