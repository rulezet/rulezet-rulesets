rule TTP_XOR_MULT_DOSStub_24b0 {
  strings:
    $key_24b0 = { 70 d8 [2] 04 c0 [2] 43 c2 [2] 04 d3 [2] 4a df [2] 46 d5 [2] 51 de [2] 4a 90 [2] 77 }

  condition:
    any of them
}