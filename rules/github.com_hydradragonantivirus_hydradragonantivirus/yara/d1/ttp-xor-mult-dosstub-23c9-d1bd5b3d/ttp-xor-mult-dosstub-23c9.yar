rule TTP_XOR_MULT_DOSStub_23c9 {
  strings:
    $key_23c9 = { 77 a1 [2] 03 b9 [2] 44 bb [2] 03 aa [2] 4d a6 [2] 41 ac [2] 56 a7 [2] 4d e9 [2] 70 }

  condition:
    any of them
}