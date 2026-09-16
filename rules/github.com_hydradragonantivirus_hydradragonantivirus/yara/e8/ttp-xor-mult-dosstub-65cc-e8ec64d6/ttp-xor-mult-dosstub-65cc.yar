rule TTP_XOR_MULT_DOSStub_65cc {
  strings:
    $key_65cc = { 31 a4 [2] 45 bc [2] 02 be [2] 45 af [2] 0b a3 [2] 07 a9 [2] 10 a2 [2] 0b ec [2] 36 }

  condition:
    any of them
}