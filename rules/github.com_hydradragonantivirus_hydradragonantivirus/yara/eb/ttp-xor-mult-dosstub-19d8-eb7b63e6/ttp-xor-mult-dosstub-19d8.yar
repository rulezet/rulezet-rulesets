rule TTP_XOR_MULT_DOSStub_19d8 {
  strings:
    $key_19d8 = { 4d b0 [2] 39 a8 [2] 7e aa [2] 39 bb [2] 77 b7 [2] 7b bd [2] 6c b6 [2] 77 f8 [2] 4a }

  condition:
    any of them
}