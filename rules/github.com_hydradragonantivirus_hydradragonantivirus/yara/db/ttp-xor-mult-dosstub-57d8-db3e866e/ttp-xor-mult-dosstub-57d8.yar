rule TTP_XOR_MULT_DOSStub_57d8 {
  strings:
    $key_57d8 = { 03 b0 [2] 77 a8 [2] 30 aa [2] 77 bb [2] 39 b7 [2] 35 bd [2] 22 b6 [2] 39 f8 [2] 04 }

  condition:
    any of them
}