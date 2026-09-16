rule TTP_XOR_MULT_DOSStub_4cd4 {
  strings:
    $key_4cd4 = { 18 bc [2] 6c a4 [2] 2b a6 [2] 6c b7 [2] 22 bb [2] 2e b1 [2] 39 ba [2] 22 f4 [2] 1f }

  condition:
    any of them
}