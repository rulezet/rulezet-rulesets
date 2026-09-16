rule TTP_XOR_MULT_DOSStub_15c2 {
  strings:
    $key_15c2 = { 41 aa [2] 35 b2 [2] 72 b0 [2] 35 a1 [2] 7b ad [2] 77 a7 [2] 60 ac [2] 7b e2 [2] 46 }

  condition:
    any of them
}