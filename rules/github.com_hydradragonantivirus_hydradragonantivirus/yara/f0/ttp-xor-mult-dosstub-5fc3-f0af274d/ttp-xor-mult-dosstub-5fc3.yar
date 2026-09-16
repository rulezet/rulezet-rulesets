rule TTP_XOR_MULT_DOSStub_5fc3 {
  strings:
    $key_5fc3 = { 0b ab [2] 7f b3 [2] 38 b1 [2] 7f a0 [2] 31 ac [2] 3d a6 [2] 2a ad [2] 31 e3 [2] 0c }

  condition:
    any of them
}