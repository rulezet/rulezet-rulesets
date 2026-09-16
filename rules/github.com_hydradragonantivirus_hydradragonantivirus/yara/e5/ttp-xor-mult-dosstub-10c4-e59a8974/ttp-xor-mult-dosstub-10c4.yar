rule TTP_XOR_MULT_DOSStub_10c4 {
  strings:
    $key_10c4 = { 44 ac [2] 30 b4 [2] 77 b6 [2] 30 a7 [2] 7e ab [2] 72 a1 [2] 65 aa [2] 7e e4 [2] 43 }

  condition:
    any of them
}