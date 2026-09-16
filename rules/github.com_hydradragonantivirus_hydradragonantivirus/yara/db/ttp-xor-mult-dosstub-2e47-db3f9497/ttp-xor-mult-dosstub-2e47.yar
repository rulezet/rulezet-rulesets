rule TTP_XOR_MULT_DOSStub_2e47 {
  strings:
    $key_2e47 = { 7a 2f [2] 0e 37 [2] 49 35 [2] 0e 24 [2] 40 28 [2] 4c 22 [2] 5b 29 [2] 40 67 [2] 7d }

  condition:
    any of them
}