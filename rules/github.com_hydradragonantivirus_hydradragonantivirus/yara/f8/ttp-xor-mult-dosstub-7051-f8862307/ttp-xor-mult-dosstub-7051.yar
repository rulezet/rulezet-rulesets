rule TTP_XOR_MULT_DOSStub_7051 {
  strings:
    $key_7051 = { 24 39 [2] 50 21 [2] 17 23 [2] 50 32 [2] 1e 3e [2] 12 34 [2] 05 3f [2] 1e 71 [2] 23 }

  condition:
    any of them
}