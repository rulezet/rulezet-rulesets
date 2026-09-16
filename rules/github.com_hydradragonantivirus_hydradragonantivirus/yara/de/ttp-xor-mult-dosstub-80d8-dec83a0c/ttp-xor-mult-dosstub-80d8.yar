rule TTP_XOR_MULT_DOSStub_80d8 {
  strings:
    $key_80d8 = { d4 b0 [2] a0 a8 [2] e7 aa [2] a0 bb [2] ee b7 [2] e2 bd [2] f5 b6 [2] ee f8 [2] d3 }

  condition:
    any of them
}