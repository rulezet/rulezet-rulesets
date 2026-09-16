rule TTP_XOR_MULT_DOSStub_1e46 {
  strings:
    $key_1e46 = { 4a 2e [2] 3e 36 [2] 79 34 [2] 3e 25 [2] 70 29 [2] 7c 23 [2] 6b 28 [2] 70 66 [2] 4d }

  condition:
    any of them
}