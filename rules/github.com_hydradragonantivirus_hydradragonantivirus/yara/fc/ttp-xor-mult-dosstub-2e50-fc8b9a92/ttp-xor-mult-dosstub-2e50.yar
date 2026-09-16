rule TTP_XOR_MULT_DOSStub_2e50 {
  strings:
    $key_2e50 = { 7a 38 [2] 0e 20 [2] 49 22 [2] 0e 33 [2] 40 3f [2] 4c 35 [2] 5b 3e [2] 40 70 [2] 7d }

  condition:
    any of them
}