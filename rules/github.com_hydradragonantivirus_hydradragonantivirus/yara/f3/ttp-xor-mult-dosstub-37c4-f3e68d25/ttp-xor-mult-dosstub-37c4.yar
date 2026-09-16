rule TTP_XOR_MULT_DOSStub_37c4 {
  strings:
    $key_37c4 = { 63 ac [2] 17 b4 [2] 50 b6 [2] 17 a7 [2] 59 ab [2] 55 a1 [2] 42 aa [2] 59 e4 [2] 64 }

  condition:
    any of them
}