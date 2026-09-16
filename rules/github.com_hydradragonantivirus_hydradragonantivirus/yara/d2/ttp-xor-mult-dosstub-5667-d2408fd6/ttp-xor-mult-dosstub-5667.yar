rule TTP_XOR_MULT_DOSStub_5667 {
  strings:
    $key_5667 = { 02 0f [2] 76 17 [2] 31 15 [2] 76 04 [2] 38 08 [2] 34 02 [2] 23 09 [2] 38 47 [2] 05 }

  condition:
    any of them
}