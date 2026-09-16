rule TTP_XOR_MULT_DOSStub_1cd4 {
  strings:
    $key_1cd4 = { 48 bc [2] 3c a4 [2] 7b a6 [2] 3c b7 [2] 72 bb [2] 7e b1 [2] 69 ba [2] 72 f4 [2] 4f }

  condition:
    any of them
}