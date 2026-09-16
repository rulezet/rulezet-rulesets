rule TTP_XOR_MULT_DOSStub_4050 {
  strings:
    $key_4050 = { 14 38 [2] 60 20 [2] 27 22 [2] 60 33 [2] 2e 3f [2] 22 35 [2] 35 3e [2] 2e 70 [2] 13 }

  condition:
    any of them
}