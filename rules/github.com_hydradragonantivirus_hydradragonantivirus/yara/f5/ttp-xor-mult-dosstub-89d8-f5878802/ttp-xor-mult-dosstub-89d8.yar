rule TTP_XOR_MULT_DOSStub_89d8 {
  strings:
    $key_89d8 = { dd b0 [2] a9 a8 [2] ee aa [2] a9 bb [2] e7 b7 [2] eb bd [2] fc b6 [2] e7 f8 [2] da }

  condition:
    any of them
}