rule TTP_XOR_MULT_DOSStub_3cd4 {
  strings:
    $key_3cd4 = { 68 bc [2] 1c a4 [2] 5b a6 [2] 1c b7 [2] 52 bb [2] 5e b1 [2] 49 ba [2] 52 f4 [2] 6f }

  condition:
    any of them
}