rule TTP_XOR_MULT_DOSStub_07c4 {
  strings:
    $key_07c4 = { 53 ac [2] 27 b4 [2] 60 b6 [2] 27 a7 [2] 69 ab [2] 65 a1 [2] 72 aa [2] 69 e4 [2] 54 }

  condition:
    any of them
}