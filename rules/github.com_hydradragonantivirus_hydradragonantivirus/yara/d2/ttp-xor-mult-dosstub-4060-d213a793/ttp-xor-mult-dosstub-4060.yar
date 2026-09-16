rule TTP_XOR_MULT_DOSStub_4060 {
  strings:
    $key_4060 = { 14 08 [2] 60 10 [2] 27 12 [2] 60 03 [2] 2e 0f [2] 22 05 [2] 35 0e [2] 2e 40 [2] 13 }

  condition:
    any of them
}