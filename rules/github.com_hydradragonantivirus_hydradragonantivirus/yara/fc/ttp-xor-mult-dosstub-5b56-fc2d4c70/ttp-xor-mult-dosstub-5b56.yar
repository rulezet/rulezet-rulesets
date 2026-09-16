rule TTP_XOR_MULT_DOSStub_5b56 {
  strings:
    $key_5b56 = { 0f 3e [2] 7b 26 [2] 3c 24 [2] 7b 35 [2] 35 39 [2] 39 33 [2] 2e 38 [2] 35 76 [2] 08 }

  condition:
    any of them
}