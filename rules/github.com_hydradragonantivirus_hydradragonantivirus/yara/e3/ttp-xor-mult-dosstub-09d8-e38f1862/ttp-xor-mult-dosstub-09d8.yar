rule TTP_XOR_MULT_DOSStub_09d8 {
  strings:
    $key_09d8 = { 5d b0 [2] 29 a8 [2] 6e aa [2] 29 bb [2] 67 b7 [2] 6b bd [2] 7c b6 [2] 67 f8 [2] 5a }

  condition:
    any of them
}