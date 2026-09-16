rule TTP_XOR_MULT_DOSStub_c5c9 {
  strings:
    $key_c5c9 = { 91 a1 [2] e5 b9 [2] a2 bb [2] e5 aa [2] ab a6 [2] a7 ac [2] b0 a7 [2] ab e9 [2] 96 }

  condition:
    any of them
}