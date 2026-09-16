rule TTP_XOR_MULT_DOSStub_08d4 {
  strings:
    $key_08d4 = { 5c bc [2] 28 a4 [2] 6f a6 [2] 28 b7 [2] 66 bb [2] 6a b1 [2] 7d ba [2] 66 f4 [2] 5b }

  condition:
    any of them
}