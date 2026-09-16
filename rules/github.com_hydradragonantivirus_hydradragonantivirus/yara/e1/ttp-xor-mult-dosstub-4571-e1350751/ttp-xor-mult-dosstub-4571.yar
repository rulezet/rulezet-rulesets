rule TTP_XOR_MULT_DOSStub_4571 {
  strings:
    $key_4571 = { 11 19 [2] 65 01 [2] 22 03 [2] 65 12 [2] 2b 1e [2] 27 14 [2] 30 1f [2] 2b 51 [2] 16 }

  condition:
    any of them
}