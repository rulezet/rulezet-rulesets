rule TTP_XOR_MULT_DOSStub_55c2 {
  strings:
    $key_55c2 = { 01 aa [2] 75 b2 [2] 32 b0 [2] 75 a1 [2] 3b ad [2] 37 a7 [2] 20 ac [2] 3b e2 [2] 06 }

  condition:
    any of them
}