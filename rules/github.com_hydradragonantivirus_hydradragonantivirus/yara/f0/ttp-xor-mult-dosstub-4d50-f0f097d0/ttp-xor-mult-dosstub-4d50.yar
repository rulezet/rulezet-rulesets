rule TTP_XOR_MULT_DOSStub_4d50 {
  strings:
    $key_4d50 = { 19 38 [2] 6d 20 [2] 2a 22 [2] 6d 33 [2] 23 3f [2] 2f 35 [2] 38 3e [2] 23 70 [2] 1e }

  condition:
    any of them
}