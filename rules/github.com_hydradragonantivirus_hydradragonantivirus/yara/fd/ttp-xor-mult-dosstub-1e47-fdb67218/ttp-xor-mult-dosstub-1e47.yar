rule TTP_XOR_MULT_DOSStub_1e47 {
  strings:
    $key_1e47 = { 4a 2f [2] 3e 37 [2] 79 35 [2] 3e 24 [2] 70 28 [2] 7c 22 [2] 6b 29 [2] 70 67 [2] 4d }

  condition:
    any of them
}