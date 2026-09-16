rule TTP_XOR_MULT_DOSStub_44b4 {
  strings:
    $key_44b4 = { 10 dc [2] 64 c4 [2] 23 c6 [2] 64 d7 [2] 2a db [2] 26 d1 [2] 31 da [2] 2a 94 [2] 17 }

  condition:
    any of them
}