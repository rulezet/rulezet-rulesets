rule TTP_XOR_MULT_DOSStub_6640 {
  strings:
    $key_6640 = { 32 28 [2] 46 30 [2] 01 32 [2] 46 23 [2] 08 2f [2] 04 25 [2] 13 2e [2] 08 60 [2] 35 }

  condition:
    any of them
}