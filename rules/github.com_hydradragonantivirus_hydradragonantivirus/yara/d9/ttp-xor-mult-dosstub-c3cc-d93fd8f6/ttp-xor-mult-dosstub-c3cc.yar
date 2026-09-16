rule TTP_XOR_MULT_DOSStub_c3cc {
  strings:
    $key_c3cc = { 97 a4 [2] e3 bc [2] a4 be [2] e3 af [2] ad a3 [2] a1 a9 [2] b6 a2 [2] ad ec [2] 90 }

  condition:
    any of them
}