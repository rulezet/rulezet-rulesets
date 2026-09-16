rule TTP_XOR_MULT_DOSStub_0da9 {
  strings:
    $key_0da9 = { 59 c1 [2] 2d d9 [2] 6a db [2] 2d ca [2] 63 c6 [2] 6f cc [2] 78 c7 [2] 63 89 [2] 5e }

  condition:
    any of them
}