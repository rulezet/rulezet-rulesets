rule TTP_XOR_MULT_DOSStub_2dd8 {
  strings:
    $key_2dd8 = { 79 b0 [2] 0d a8 [2] 4a aa [2] 0d bb [2] 43 b7 [2] 4f bd [2] 58 b6 [2] 43 f8 [2] 7e }

  condition:
    any of them
}