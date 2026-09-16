rule TTP_XOR_MULT_DOSStub_7e56 {
  strings:
    $key_7e56 = { 2a 3e [2] 5e 26 [2] 19 24 [2] 5e 35 [2] 10 39 [2] 1c 33 [2] 0b 38 [2] 10 76 [2] 2d }

  condition:
    any of them
}