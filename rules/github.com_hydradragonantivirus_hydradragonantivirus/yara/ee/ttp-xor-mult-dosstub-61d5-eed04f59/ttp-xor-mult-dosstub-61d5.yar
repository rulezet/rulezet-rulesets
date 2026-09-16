rule TTP_XOR_MULT_DOSStub_61d5 {
  strings:
    $key_61d5 = { 35 bd [2] 41 a5 [2] 06 a7 [2] 41 b6 [2] 0f ba [2] 03 b0 [2] 14 bb [2] 0f f5 [2] 32 }

  condition:
    any of them
}