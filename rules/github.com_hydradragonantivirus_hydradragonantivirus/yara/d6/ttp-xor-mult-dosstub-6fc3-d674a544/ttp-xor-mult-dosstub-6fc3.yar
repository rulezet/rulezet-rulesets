rule TTP_XOR_MULT_DOSStub_6fc3 {
  strings:
    $key_6fc3 = { 3b ab [2] 4f b3 [2] 08 b1 [2] 4f a0 [2] 01 ac [2] 0d a6 [2] 1a ad [2] 01 e3 [2] 3c }

  condition:
    any of them
}