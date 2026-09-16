rule TTP_XOR_MULT_DOSStub_2571 {
  strings:
    $key_2571 = { 71 19 [2] 05 01 [2] 42 03 [2] 05 12 [2] 4b 1e [2] 47 14 [2] 50 1f [2] 4b 51 [2] 76 }

  condition:
    any of them
}