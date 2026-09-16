rule TTP_XOR_MULT_DOSStub_7a50 {
  strings:
    $key_7a50 = { 2e 38 [2] 5a 20 [2] 1d 22 [2] 5a 33 [2] 14 3f [2] 18 35 [2] 0f 3e [2] 14 70 [2] 29 }

  condition:
    any of them
}