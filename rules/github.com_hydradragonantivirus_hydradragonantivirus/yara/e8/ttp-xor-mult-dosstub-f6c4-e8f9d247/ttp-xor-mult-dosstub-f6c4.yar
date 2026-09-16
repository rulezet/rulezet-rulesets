rule TTP_XOR_MULT_DOSStub_f6c4 {
  strings:
    $key_f6c4 = { a2 ac [2] d6 b4 [2] 91 b6 [2] d6 a7 [2] 98 ab [2] 94 a1 [2] 83 aa [2] 98 e4 [2] a5 }

  condition:
    any of them
}