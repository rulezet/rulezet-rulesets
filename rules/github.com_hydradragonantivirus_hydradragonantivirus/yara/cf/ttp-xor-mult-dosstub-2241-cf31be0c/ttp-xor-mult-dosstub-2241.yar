rule TTP_XOR_MULT_DOSStub_2241 {
  strings:
    $key_2241 = { 76 29 [2] 02 31 [2] 45 33 [2] 02 22 [2] 4c 2e [2] 40 24 [2] 57 2f [2] 4c 61 [2] 71 }

  condition:
    any of them
}