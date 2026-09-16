rule TTP_XOR_MULT_DOSStub_27c2 {
  strings:
    $key_27c2 = { 73 aa [2] 07 b2 [2] 40 b0 [2] 07 a1 [2] 49 ad [2] 45 a7 [2] 52 ac [2] 49 e2 [2] 74 }

  condition:
    any of them
}