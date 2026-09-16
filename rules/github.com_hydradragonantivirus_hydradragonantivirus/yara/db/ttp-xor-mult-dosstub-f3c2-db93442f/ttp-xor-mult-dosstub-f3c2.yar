rule TTP_XOR_MULT_DOSStub_f3c2 {
  strings:
    $key_f3c2 = { a7 aa [2] d3 b2 [2] 94 b0 [2] d3 a1 [2] 9d ad [2] 91 a7 [2] 86 ac [2] 9d e2 [2] a0 }

  condition:
    any of them
}