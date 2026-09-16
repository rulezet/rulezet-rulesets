rule TTP_XOR_MULT_DOSStub_1e40 {
  strings:
    $key_1e40 = { 4a 28 [2] 3e 30 [2] 79 32 [2] 3e 23 [2] 70 2f [2] 7c 25 [2] 6b 2e [2] 70 60 [2] 4d }

  condition:
    any of them
}