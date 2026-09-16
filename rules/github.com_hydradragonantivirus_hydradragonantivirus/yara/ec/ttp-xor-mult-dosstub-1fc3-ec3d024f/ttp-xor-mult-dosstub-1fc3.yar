rule TTP_XOR_MULT_DOSStub_1fc3 {
  strings:
    $key_1fc3 = { 4b ab [2] 3f b3 [2] 78 b1 [2] 3f a0 [2] 71 ac [2] 7d a6 [2] 6a ad [2] 71 e3 [2] 4c }

  condition:
    any of them
}