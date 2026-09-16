rule TTP_XOR_MULT_DOSStub_5cd3 {
  strings:
    $key_5cd3 = { 08 bb [2] 7c a3 [2] 3b a1 [2] 7c b0 [2] 32 bc [2] 3e b6 [2] 29 bd [2] 32 f3 [2] 0f }

  condition:
    any of them
}