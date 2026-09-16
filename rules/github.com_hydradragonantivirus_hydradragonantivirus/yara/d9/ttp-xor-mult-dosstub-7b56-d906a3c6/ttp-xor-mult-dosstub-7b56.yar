rule TTP_XOR_MULT_DOSStub_7b56 {
  strings:
    $key_7b56 = { 2f 3e [2] 5b 26 [2] 1c 24 [2] 5b 35 [2] 15 39 [2] 19 33 [2] 0e 38 [2] 15 76 [2] 28 }

  condition:
    any of them
}