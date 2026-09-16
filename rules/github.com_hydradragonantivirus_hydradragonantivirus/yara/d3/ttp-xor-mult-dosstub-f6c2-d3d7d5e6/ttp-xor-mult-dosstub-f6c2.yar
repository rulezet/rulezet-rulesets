rule TTP_XOR_MULT_DOSStub_f6c2 {
  strings:
    $key_f6c2 = { a2 aa [2] d6 b2 [2] 91 b0 [2] d6 a1 [2] 98 ad [2] 94 a7 [2] 83 ac [2] 98 e2 [2] a5 }

  condition:
    any of them
}