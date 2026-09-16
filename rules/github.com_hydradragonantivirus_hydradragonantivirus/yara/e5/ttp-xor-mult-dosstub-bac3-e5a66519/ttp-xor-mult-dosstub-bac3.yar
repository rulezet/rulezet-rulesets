rule TTP_XOR_MULT_DOSStub_bac3 {
  strings:
    $key_bac3 = { ee ab [2] 9a b3 [2] dd b1 [2] 9a a0 [2] d4 ac [2] d8 a6 [2] cf ad [2] d4 e3 [2] e9 }

  condition:
    any of them
}