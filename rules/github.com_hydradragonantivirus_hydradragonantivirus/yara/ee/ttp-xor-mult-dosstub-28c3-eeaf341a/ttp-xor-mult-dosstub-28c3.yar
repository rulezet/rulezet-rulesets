rule TTP_XOR_MULT_DOSStub_28c3 {
  strings:
    $key_28c3 = { 7c ab [2] 08 b3 [2] 4f b1 [2] 08 a0 [2] 46 ac [2] 4a a6 [2] 5d ad [2] 46 e3 [2] 7b }

  condition:
    any of them
}