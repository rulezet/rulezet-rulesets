rule TTP_XOR_MULT_DOSStub_b2cc {
  strings:
    $key_b2cc = { e6 a4 [2] 92 bc [2] d5 be [2] 92 af [2] dc a3 [2] d0 a9 [2] c7 a2 [2] dc ec [2] e1 }

  condition:
    any of them
}