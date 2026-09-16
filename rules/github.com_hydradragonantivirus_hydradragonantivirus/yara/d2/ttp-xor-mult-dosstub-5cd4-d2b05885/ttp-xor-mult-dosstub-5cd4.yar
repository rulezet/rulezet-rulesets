rule TTP_XOR_MULT_DOSStub_5cd4 {
  strings:
    $key_5cd4 = { 08 bc [2] 7c a4 [2] 3b a6 [2] 7c b7 [2] 32 bb [2] 3e b1 [2] 29 ba [2] 32 f4 [2] 0f }

  condition:
    any of them
}