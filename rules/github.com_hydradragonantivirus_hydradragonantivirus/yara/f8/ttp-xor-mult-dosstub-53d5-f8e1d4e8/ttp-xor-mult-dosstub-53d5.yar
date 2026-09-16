rule TTP_XOR_MULT_DOSStub_53d5 {
  strings:
    $key_53d5 = { 07 bd [2] 73 a5 [2] 34 a7 [2] 73 b6 [2] 3d ba [2] 31 b0 [2] 26 bb [2] 3d f5 [2] 00 }

  condition:
    any of them
}