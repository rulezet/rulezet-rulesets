rule TTP_XOR_MULT_DOSStub_7cd2 {
  strings:
    $key_7cd2 = { 28 ba [2] 5c a2 [2] 1b a0 [2] 5c b1 [2] 12 bd [2] 1e b7 [2] 09 bc [2] 12 f2 [2] 2f }

  condition:
    any of them
}