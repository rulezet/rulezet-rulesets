rule TTP_XOR_MULT_DOSStub_dfc0 {
  strings:
    $key_dfc0 = { 8b a8 [2] ff b0 [2] b8 b2 [2] ff a3 [2] b1 af [2] bd a5 [2] aa ae [2] b1 e0 [2] 8c }

  condition:
    any of them
}