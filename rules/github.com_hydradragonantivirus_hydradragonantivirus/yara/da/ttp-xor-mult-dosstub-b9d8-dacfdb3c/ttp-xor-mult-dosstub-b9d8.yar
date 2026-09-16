rule TTP_XOR_MULT_DOSStub_b9d8 {
  strings:
    $key_b9d8 = { ed b0 [2] 99 a8 [2] de aa [2] 99 bb [2] d7 b7 [2] db bd [2] cc b6 [2] d7 f8 [2] ea }

  condition:
    any of them
}