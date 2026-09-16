rule TTP_XOR_MULT_DOSStub_feb0 {
  strings:
    $key_feb0 = { aa d8 [2] de c0 [2] 99 c2 [2] de d3 [2] 90 df [2] 9c d5 [2] 8b de [2] 90 90 [2] ad }

  condition:
    any of them
}