rule TTP_XOR_MULT_DOSStub_f3c4 {
  strings:
    $key_f3c4 = { a7 ac [2] d3 b4 [2] 94 b6 [2] d3 a7 [2] 9d ab [2] 91 a1 [2] 86 aa [2] 9d e4 [2] a0 }

  condition:
    any of them
}