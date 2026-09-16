rule TTP_XOR_MULT_DOSStub_2556 {
  strings:
    $key_2556 = { 71 3e [2] 05 26 [2] 42 24 [2] 05 35 [2] 4b 39 [2] 47 33 [2] 50 38 [2] 4b 76 [2] 76 }

  condition:
    any of them
}