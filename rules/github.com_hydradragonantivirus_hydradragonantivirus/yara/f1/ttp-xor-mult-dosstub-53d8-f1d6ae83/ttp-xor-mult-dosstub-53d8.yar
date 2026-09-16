rule TTP_XOR_MULT_DOSStub_53d8 {
  strings:
    $key_53d8 = { 07 b0 [2] 73 a8 [2] 34 aa [2] 73 bb [2] 3d b7 [2] 31 bd [2] 26 b6 [2] 3d f8 [2] 00 }

  condition:
    any of them
}