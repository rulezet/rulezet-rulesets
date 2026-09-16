rule TTP_XOR_MULT_DOSStub_0589 {
  strings:
    $key_0589 = { 51 e1 [2] 25 f9 [2] 62 fb [2] 25 ea [2] 6b e6 [2] 67 ec [2] 70 e7 [2] 6b a9 [2] 56 }

  condition:
    any of them
}