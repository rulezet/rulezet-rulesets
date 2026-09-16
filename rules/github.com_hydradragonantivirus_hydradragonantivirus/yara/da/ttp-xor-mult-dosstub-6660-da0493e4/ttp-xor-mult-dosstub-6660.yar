rule TTP_XOR_MULT_DOSStub_6660 {
  strings:
    $key_6660 = { 32 08 [2] 46 10 [2] 01 12 [2] 46 03 [2] 08 0f [2] 04 05 [2] 13 0e [2] 08 40 [2] 35 }

  condition:
    any of them
}