rule TTP_XOR_MULT_DOSStub_39d8 {
  strings:
    $key_39d8 = { 6d b0 [2] 19 a8 [2] 5e aa [2] 19 bb [2] 57 b7 [2] 5b bd [2] 4c b6 [2] 57 f8 [2] 6a }

  condition:
    any of them
}