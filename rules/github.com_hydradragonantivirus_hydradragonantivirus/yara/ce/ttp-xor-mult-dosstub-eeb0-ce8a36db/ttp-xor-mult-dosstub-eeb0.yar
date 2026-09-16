rule TTP_XOR_MULT_DOSStub_eeb0 {
  strings:
    $key_eeb0 = { ba d8 [2] ce c0 [2] 89 c2 [2] ce d3 [2] 80 df [2] 8c d5 [2] 9b de [2] 80 90 [2] bd }

  condition:
    any of them
}