rule TTP_XOR_MULT_DOSStub_5d50 {
  strings:
    $key_5d50 = { 09 38 [2] 7d 20 [2] 3a 22 [2] 7d 33 [2] 33 3f [2] 3f 35 [2] 28 3e [2] 33 70 [2] 0e }

  condition:
    any of them
}