rule TTP_XOR_MULT_DOSStub_4b56 {
  strings:
    $key_4b56 = { 1f 3e [2] 6b 26 [2] 2c 24 [2] 6b 35 [2] 25 39 [2] 29 33 [2] 3e 38 [2] 25 76 [2] 18 }

  condition:
    any of them
}