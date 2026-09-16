rule TTP_XOR_MULT_DOSStub_2e70 {
  strings:
    $key_2e70 = { 7a 18 [2] 0e 00 [2] 49 02 [2] 0e 13 [2] 40 1f [2] 4c 15 [2] 5b 1e [2] 40 50 [2] 7d }

  condition:
    any of them
}