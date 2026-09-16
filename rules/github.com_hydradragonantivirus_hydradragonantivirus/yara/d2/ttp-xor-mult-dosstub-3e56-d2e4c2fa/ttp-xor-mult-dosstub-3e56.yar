rule TTP_XOR_MULT_DOSStub_3e56 {
  strings:
    $key_3e56 = { 6a 3e [2] 1e 26 [2] 59 24 [2] 1e 35 [2] 50 39 [2] 5c 33 [2] 4b 38 [2] 50 76 [2] 6d }

  condition:
    any of them
}