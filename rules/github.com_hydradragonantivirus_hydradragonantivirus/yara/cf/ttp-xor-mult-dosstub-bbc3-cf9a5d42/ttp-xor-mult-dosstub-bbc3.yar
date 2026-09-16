rule TTP_XOR_MULT_DOSStub_bbc3 {
  strings:
    $key_bbc3 = { ef ab [2] 9b b3 [2] dc b1 [2] 9b a0 [2] d5 ac [2] d9 a6 [2] ce ad [2] d5 e3 [2] e8 }

  condition:
    any of them
}