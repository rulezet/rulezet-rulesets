rule TTP_XOR_MULT_DOSStub_7066 {
  strings:
    $key_7066 = { 24 0e [2] 50 16 [2] 17 14 [2] 50 05 [2] 1e 09 [2] 12 03 [2] 05 08 [2] 1e 46 [2] 23 }

  condition:
    any of them
}