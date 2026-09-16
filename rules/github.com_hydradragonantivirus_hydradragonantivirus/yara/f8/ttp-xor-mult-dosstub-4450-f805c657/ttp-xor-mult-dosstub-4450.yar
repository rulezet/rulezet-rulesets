rule TTP_XOR_MULT_DOSStub_4450 {
  strings:
    $key_4450 = { 10 38 [2] 64 20 [2] 23 22 [2] 64 33 [2] 2a 3f [2] 26 35 [2] 31 3e [2] 2a 70 [2] 17 }

  condition:
    any of them
}