rule TTP_XOR_MULT_DOSStub_f0c9 {
  strings:
    $key_f0c9 = { a4 a1 [2] d0 b9 [2] 97 bb [2] d0 aa [2] 9e a6 [2] 92 ac [2] 85 a7 [2] 9e e9 [2] a3 }

  condition:
    any of them
}