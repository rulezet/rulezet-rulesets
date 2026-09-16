rule TTP_XOR_MULT_DOSStub_2577 {
  strings:
    $key_2577 = { 71 1f [2] 05 07 [2] 42 05 [2] 05 14 [2] 4b 18 [2] 47 12 [2] 50 19 [2] 4b 57 [2] 76 }

  condition:
    any of them
}