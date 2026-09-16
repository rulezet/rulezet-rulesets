rule TTP_XOR_MULT_DOSStub_6b46 {
  strings:
    $key_6b46 = { 3f 2e [2] 4b 36 [2] 0c 34 [2] 4b 25 [2] 05 29 [2] 09 23 [2] 1e 28 [2] 05 66 [2] 38 }

  condition:
    any of them
}