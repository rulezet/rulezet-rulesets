rule TTP_XOR_MULT_DOSStub_7050 {
  strings:
    $key_7050 = { 24 38 [2] 50 20 [2] 17 22 [2] 50 33 [2] 1e 3f [2] 12 35 [2] 05 3e [2] 1e 70 [2] 23 }

  condition:
    any of them
}