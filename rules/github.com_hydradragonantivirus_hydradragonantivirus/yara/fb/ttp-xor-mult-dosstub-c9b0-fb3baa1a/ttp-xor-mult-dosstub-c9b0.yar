rule TTP_XOR_MULT_DOSStub_c9b0 {
  strings:
    $key_c9b0 = { 9d d8 [2] e9 c0 [2] ae c2 [2] e9 d3 [2] a7 df [2] ab d5 [2] bc de [2] a7 90 [2] 9a }

  condition:
    any of them
}