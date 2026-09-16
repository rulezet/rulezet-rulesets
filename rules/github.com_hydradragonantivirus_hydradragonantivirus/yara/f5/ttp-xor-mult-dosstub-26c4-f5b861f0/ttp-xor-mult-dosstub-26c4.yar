rule TTP_XOR_MULT_DOSStub_26c4 {
  strings:
    $key_26c4 = { 72 ac [2] 06 b4 [2] 41 b6 [2] 06 a7 [2] 48 ab [2] 44 a1 [2] 53 aa [2] 48 e4 [2] 75 }

  condition:
    any of them
}