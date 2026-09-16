rule TTP_XOR_MULT_DOSStub_5d37 {
  strings:
    $key_5d37 = { 09 5f [2] 7d 47 [2] 3a 45 [2] 7d 54 [2] 33 58 [2] 3f 52 [2] 28 59 [2] 33 17 [2] 0e }

  condition:
    any of them
}