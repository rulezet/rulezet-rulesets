rule TTP_XOR_MULT_DOSStub_65c9 {
  strings:
    $key_65c9 = { 31 a1 [2] 45 b9 [2] 02 bb [2] 45 aa [2] 0b a6 [2] 07 ac [2] 10 a7 [2] 0b e9 [2] 36 }

  condition:
    any of them
}