rule TTP_XOR_MULT_DOSStub_2407 {
  strings:
    $key_2407 = { 70 6f [2] 04 77 [2] 43 75 [2] 04 64 [2] 4a 68 [2] 46 62 [2] 51 69 [2] 4a 27 [2] 77 }

  condition:
    any of them
}