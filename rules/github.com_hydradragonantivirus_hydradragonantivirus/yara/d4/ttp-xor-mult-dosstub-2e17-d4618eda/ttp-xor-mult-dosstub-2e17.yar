rule TTP_XOR_MULT_DOSStub_2e17 {
  strings:
    $key_2e17 = { 7a 7f [2] 0e 67 [2] 49 65 [2] 0e 74 [2] 40 78 [2] 4c 72 [2] 5b 79 [2] 40 37 [2] 7d }

  condition:
    any of them
}