rule TTP_XOR_MULT_DOSStub_c2cc {
  strings:
    $key_c2cc = { 96 a4 [2] e2 bc [2] a5 be [2] e2 af [2] ac a3 [2] a0 a9 [2] b7 a2 [2] ac ec [2] 91 }

  condition:
    any of them
}