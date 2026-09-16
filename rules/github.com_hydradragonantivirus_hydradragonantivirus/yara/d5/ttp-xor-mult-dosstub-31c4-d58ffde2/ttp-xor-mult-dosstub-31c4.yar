rule TTP_XOR_MULT_DOSStub_31c4 {
  strings:
    $key_31c4 = { 65 ac [2] 11 b4 [2] 56 b6 [2] 11 a7 [2] 5f ab [2] 53 a1 [2] 44 aa [2] 5f e4 [2] 62 }

  condition:
    any of them
}