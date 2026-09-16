rule TTP_XOR_MULT_DOSStub_69c3 {
  strings:
    $key_69c3 = { 3d ab [2] 49 b3 [2] 0e b1 [2] 49 a0 [2] 07 ac [2] 0b a6 [2] 1c ad [2] 07 e3 [2] 3a }

  condition:
    any of them
}