rule TTP_XOR_MULT_DOSStub_2461 {
  strings:
    $key_2461 = { 70 09 [2] 04 11 [2] 43 13 [2] 04 02 [2] 4a 0e [2] 46 04 [2] 51 0f [2] 4a 41 [2] 77 }

  condition:
    any of them
}