rule TTP_XOR_MULT_DOSStub_72cc {
  strings:
    $key_72cc = { 26 a4 [2] 52 bc [2] 15 be [2] 52 af [2] 1c a3 [2] 10 a9 [2] 07 a2 [2] 1c ec [2] 21 }

  condition:
    any of them
}