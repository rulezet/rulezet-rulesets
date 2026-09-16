rule TTP_XOR_MULT_DOSStub_79c3 {
  strings:
    $key_79c3 = { 2d ab [2] 59 b3 [2] 1e b1 [2] 59 a0 [2] 17 ac [2] 1b a6 [2] 0c ad [2] 17 e3 [2] 2a }

  condition:
    any of them
}