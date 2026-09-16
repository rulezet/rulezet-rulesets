rule TTP_XOR_MULT_DOSStub_7290 {
  strings:
    $key_7290 = { 26 f8 [2] 52 e0 [2] 15 e2 [2] 52 f3 [2] 1c ff [2] 10 f5 [2] 07 fe [2] 1c b0 [2] 21 }

  condition:
    any of them
}