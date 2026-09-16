rule TTP_XOR_MULT_DOSStub_05d8 {
  strings:
    $key_05d8 = { 51 b0 [2] 25 a8 [2] 62 aa [2] 25 bb [2] 6b b7 [2] 67 bd [2] 70 b6 [2] 6b f8 [2] 56 }

  condition:
    any of them
}