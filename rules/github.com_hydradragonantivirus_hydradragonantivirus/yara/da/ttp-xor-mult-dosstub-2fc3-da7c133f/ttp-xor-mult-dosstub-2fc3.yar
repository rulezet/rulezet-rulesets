rule TTP_XOR_MULT_DOSStub_2fc3 {
  strings:
    $key_2fc3 = { 7b ab [2] 0f b3 [2] 48 b1 [2] 0f a0 [2] 41 ac [2] 4d a6 [2] 5a ad [2] 41 e3 [2] 7c }

  condition:
    any of them
}