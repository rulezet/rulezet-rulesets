rule TTP_XOR_MULT_DOSStub_5076 {
  strings:
    $key_5076 = { 04 1e [2] 70 06 [2] 37 04 [2] 70 15 [2] 3e 19 [2] 32 13 [2] 25 18 [2] 3e 56 [2] 03 }

  condition:
    any of them
}