rule TTP_XOR_MULT_DOSStub_2466 {
  strings:
    $key_2466 = { 70 0e [2] 04 16 [2] 43 14 [2] 04 05 [2] 4a 09 [2] 46 03 [2] 51 08 [2] 4a 46 [2] 77 }

  condition:
    any of them
}