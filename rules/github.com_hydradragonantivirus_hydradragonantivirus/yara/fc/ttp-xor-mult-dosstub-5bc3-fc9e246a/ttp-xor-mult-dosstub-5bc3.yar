rule TTP_XOR_MULT_DOSStub_5bc3 {
  strings:
    $key_5bc3 = { 0f ab [2] 7b b3 [2] 3c b1 [2] 7b a0 [2] 35 ac [2] 39 a6 [2] 2e ad [2] 35 e3 [2] 08 }

  condition:
    any of them
}